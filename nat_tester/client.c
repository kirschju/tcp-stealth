/* 
 * Copyright (C) 2014 kirschju@sec.in.tum.de
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Under Linux/Android/OSX, compile with
 *   gcc client.c -lpthread -lpcap -o client
 * and execute as root.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#if defined _WIN64 || defined _WIN32
#include "windows_helpers.h"
#else
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* Use BSD names for the definition of the tcp header */
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* We could include <asm/types.h> but OSX needs these anyway */
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t  __u8;

/* Regular expressions used to match IP and ethernet addresses, respectively */
#define REGEX_IP_ADDR	"\"([0-9]{1,3}\\.){3}[0-9]{1,3}\""
#define REGEX_ETH_ADDR	"\"([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\""

/* Construct a sh string which first fetches the IP address of this network's
 * gateway and then looks up the corresponding ethernet address in the local
 * machine's ARP cache. */
#if defined __linux__ || defined __ANDROID__
#define SH_GET_DEFAULT_GW_ETH_ADDR				\
	"grep -w $(ip r | "					\
	"grep -Em 1 \"^default\" | "				\
	"grep -oE " REGEX_IP_ADDR ") /proc/net/arp | "		\
	"grep -oE " REGEX_ETH_ADDR
#elif defined __APPLE__ && defined __MACH__
#define SH_GET_DEFAULT_GW_ETH_ADDR				\
	"arp -na | " 						\
	"grep -w $(route -n get default | " 			\
	"grep 'gateway' | grep -oE " REGEX_IP_ADDR ") | "	\
	"grep -oE " REGEX_ETH_ADDR
#else
#define SH_GET_DEFAULT_GW_ETH_ADDR	""
#warning "Unable to build a regexp for the target architecture."
#endif /* __linux__ || __ANDROID__ */
#endif /* _WIN32 && _WIN64 */

/* Indicator of what version of the client generated the sample */
#if   defined __linux__
#define CLIENT_VERSION	0x0000
#elif defined __ANDROID__
#define CLIENT_VERSION	0x0001
#elif defined __APPLE__ && defined __MACH__
#define CLIENT_VERSION	0x0002
#elif defined _WIN64 || defined _WIN32
#define CLIENT_VERSION	0x0003
#else
#define CLIENT_VERSION	0xffff
#endif

/* Destination address of the server which collects the probes */
#define SADDR			"85.214.107.226"
#define SPORT			"12345"
/* Busywait interval used in thread synchronization context */
#define BUSYWAIT_INT_USECS	100000

/* One thread per interface */
#define MAX_THREADS		32
#define MAX_IFACE		MAX_THREADS

/* Maximum name length for one interface */
#define MAX_IFACE_NAME		256
#define MAX_INIT_TRIES		10
#define LINUXSLL_HDR_LEN	16
#define ETHERNET_HDR_LEN	14
#define IEEE80211_HDR_LEN	24
#define DLT_INVALID		254

/* This is the main payload which will be filled out by libpcap
 * and sent to the server by the main process. */
struct tcp_probe {
	__u32 saddr;
	__u32 isn;
	__u32 tsval;
	__u16 cksum;
	__u16 version;
	__u8  hw[6];
};

/* The main control structure, holds the probe itself as well as data which
 * is used to synchronize the threads */
struct probe_info {
	__u8 data_ready:1;
	__u8 dl_type[MAX_THREADS];
	pcap_t *pcap_handle[MAX_THREADS];
	pthread_t t_info[MAX_THREADS];
	char ifname[MAX_THREADS][512];
	struct tcp_probe tp;
};

/* Globally used mutex to guard the probe_info structure */
pthread_mutex_t lock;
struct probe_info pi = { 0 };

/* A simplified version of Fletcher's checksum */
__u16 fletcher(const __u8* data, size_t len)
{
	__u8 sum1 = 0, sum2 = 0, i = 0;
	while (len--) {
		sum1 += data[i++];
		sum2 += sum1;
	}
	return (sum2 << 8) | sum1;
}

/* Polls the dl_type of the specified thread and returns as soon the
 * specified thread signals to be ready or after MAX_INIT_TRIES has been
 * reached.
 */
int wait_for_thread_init(__u32 threadnr)
{
	__u8 rdy = 0;
	__u32 tries = 0;
	__u8 fail = 0;
	while (!rdy) {
		pthread_mutex_lock(&lock);
		fail = pi.dl_type[threadnr] == DLT_INVALID;
		rdy = !(pi.dl_type[threadnr] == 0 || fail) ;
		pthread_mutex_unlock(&lock);
		if (tries++ > MAX_INIT_TRIES || fail) return -1;
		usleep(BUSYWAIT_INT_USECS);
	}
	return 0;
}

void wait_for_pcap_data()
{
	__u8 rdy = 0;
	while (!rdy) {
		pthread_mutex_lock(&lock);
		rdy = pi.data_ready;
		pthread_mutex_unlock(&lock);
		usleep(BUSYWAIT_INT_USECS);
	}
	return;
}
/* Obtain the default gateway's MAC address. We need it for two major reasons:
 * 1. We can use the MAC to reasonably enough distinguish between
 *    samples in order to not double-count the same NAT box.
 * 2. We will use the OUI (1st 3 Bytes of the MAC) in order to find
 *    the manufacturer of the network card in your NAT box which will
 *    hopefully help finding the manufacturer of the NAT box.
 */
void get_gw_hwaddr(__u8 full_hwaddr)
{
#if defined _WIN32 || defined _WIN64
	__u8 hwaddr[6] = { 0 };
	unsigned long hwaddr_len = sizeof(hwaddr);
	__u32 i;

	/* We expect at most 256 entries in the routing table */
	MIB_IPFORWARDTABLE ft[256 * sizeof(MIB_IPFORWARDROW) + sizeof(DWORD)];
	unsigned long s = sizeof(ft);

	if (GetIpForwardTable(ft, &s, 0) == NO_ERROR) {
		for (i = 0; i < ft->dwNumEntries; i++) {
			if (ft->table[i].dwForwardDest == 0 && 
			    SendARP(ft->table[i].dwForwardNextHop, 0, hwaddr,
								   &hwaddr_len)
								   == NO_ERROR) {
				pthread_mutex_lock(&lock);
				memcpy(pi.tp.hw, hwaddr, sizeof(pi.tp.hw));
				pthread_mutex_unlock(&lock);
				break;
			}
		}
	}
#else
	FILE *p;
	pthread_mutex_lock(&lock);
	p = popen(SH_GET_DEFAULT_GW_ETH_ADDR, "r");
	if (!p || fscanf(p, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &pi.tp.hw[0],
							     &pi.tp.hw[1],
							     &pi.tp.hw[2],
							     &pi.tp.hw[3],
							     &pi.tp.hw[4],
							     &pi.tp.hw[5]) != 6)
		fprintf(stderr, "[!] Failed to obtain the ethernet address of\n" \
				"    the network gateway.\n");
	pclose(p);
	/* Delete the non-OUI part if the user requested it */
	if (!full_hwaddr) pi.tp.hw[3] = pi.tp.hw[4] = pi.tp.hw[5] = 0;
	pthread_mutex_unlock(&lock);
#endif
}
/* Parses the tcphdr options and tries to find the tsval option. Return value
 * is in network byte order. */
unsigned int get_tsval(struct tcphdr *th, size_t len)
{
	__u8 *p;
	/*  No options? Assume 0. */
	if (len <= sizeof(struct tcphdr)) return 0;
	/*  Truncated header options? Return 0. */
	if (th->th_off * 4 > len) return 0;
	len = th->th_off * 4 - sizeof(struct tcphdr);
	p = (unsigned char *)(th + 1);
	while (len > 0) {
		switch (*p++) {
		    case TCPOPT_NOP:
			len--;
		    break;
		    case TCPOPT_TIMESTAMP:
		    	return (len < TCPOLEN_TIMESTAMP) ? 0 : *(__u32 *)(p + 1);
		    break;
		    default:
		    	if (len < *p) return 0;
			len -= *p;
			p += *p - 1;
		    break;
		}
	}
	return 0;
}

/* Extracts the needed information from the packet as it is put onto the wire */
void collect_callback(unsigned char *args, const struct pcap_pkthdr* pkthdr,
					   const unsigned char* data)
{
	unsigned char t = *args;
	struct ip *ih;
	struct tcphdr *th;
	size_t ip_hl;

	/* We trust libpcap and do minimal sanitizing here. The only property
	 * we require is that the buffer is long enough to fit layer 2 and
	 * layer 3 headers. */
	if (pkthdr->caplen < IEEE80211_HDR_LEN + sizeof(struct ip)) {
		fprintf(stdout, "[!] Truncated packet received (1).\n");
		return;
	}
	pthread_mutex_lock(&lock);
	/* Parse packet */
	switch (pi.dl_type[t]) {
		case DLT_EN10MB:
			ih = (struct ip *)(data + ETHERNET_HDR_LEN);
		break;
		case DLT_IEEE802_11:
			ih = (struct ip *)(data + IEEE80211_HDR_LEN);
		break;
		case DLT_LINUX_SLL:
			ih = (struct ip *)(data + LINUXSLL_HDR_LEN);
		break;
		default:
			/* Should not be reached */
			fprintf(stderr, "[!] Unknown Datalink layer type.\n");
			return;
		break;
	}
	pthread_mutex_unlock(&lock);
	ip_hl = ih->ip_hl * 4;
	if (pkthdr->caplen < ((__u8 *)ih - data) + ip_hl + sizeof(struct tcphdr)) {
		fprintf(stdout, "[!] Truncated packet received (2).\n");
		return;
	}
	th = (struct tcphdr *)((__u8 *)ih + ip_hl);
	/* Lock mutex and tell the main thread that there is new data */
	pthread_mutex_lock(&lock);
	pi.tp.saddr = *(__u32 *)&ih->ip_src;
	pi.tp.isn = th->th_seq;
	pi.tp.version = htons(CLIENT_VERSION);
	pi.tp.tsval = get_tsval(th, pkthdr->caplen - ((__u8 *)th - data));

	pi.data_ready = 1;
	pthread_mutex_unlock(&lock);
	return;
}

/* Sets up libpcap and registers collect_callback() to be called upon
 * arrival of each packet that passed the specified filter */
void *capture_thread(void *arg)
{
	pcap_t *pcap;
	int dl_type;
	__u32 t_nr;
	char errbuf[PCAP_ERRBUF_SIZE];
	char l_ifname[MAX_IFACE_NAME];
	struct bpf_program fp;
	char *filter_exp = "tcp[tcpflags] & (tcp-syn) != 0 " \
			   "and tcp port " SPORT " " \
			   "and dst " SADDR;
	if (!arg) return NULL;
	t_nr = *(__u32 *)arg;
	pthread_mutex_lock(&lock);
	strncpy(l_ifname, pi.ifname[t_nr], MAX_IFACE_NAME - 1);
	pthread_mutex_unlock(&lock);

	/* Open the capture device and check if datalink layer can be handled
	 * by the colloect_callback() function */
	pcap = pcap_open_live(l_ifname, BUFSIZ, 0, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "[!] Couldn't open device: %s\n", errbuf);
		goto out;
	}
	dl_type = pcap_datalink(pcap);
	if (dl_type != DLT_EN10MB && 
	    dl_type != DLT_IEEE802_11 &&
	    dl_type != DLT_LINUX_SLL) goto out2;

	/* Compile and apply the filter */
	if (pcap_compile(pcap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "[!] Couldn't parse filter: %s\n",									pcap_geterr(pcap));
		goto out2;
	}
	if (pcap_setfilter(pcap, &fp) < 0) {
		fprintf(stderr, "[!] Couldn't install filter: %s\n",
						 pcap_geterr(pcap));
		goto out3;
	}
	pcap_freecode(&fp);

	/* Tell the the main thread that this thread is ready to capture data */
	pthread_mutex_lock(&lock);
	pi.dl_type[t_nr] = dl_type;
	pi.pcap_handle[t_nr] = pcap;
	pthread_mutex_unlock(&lock);
	/* Start capturing */
	pcap_loop(pcap, -1, collect_callback, (void *)&t_nr);
	/* Should not be reached */
out3:
	pcap_freecode(&fp);
out2:
	pcap_close(pcap);
out:
	pthread_mutex_lock(&lock);
	pi.dl_type[t_nr] = DLT_INVALID;
	pthread_mutex_unlock(&lock);
	return NULL;
}

int pcap_supports_any_dev(pcap_if_t *alldevs)
{
	pcap_if_t *d = NULL;

	for (d = alldevs; d; d = d->next)
		if (!strcmp(d->name, "any")) return 1;

	return 0;
}

int pcap_setup()
{
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	pcap_if_t *alldevs;
	pcap_if_t *d = NULL;
	__u32 i = 0;
	pthread_t t_info;

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		fprintf(stderr,"[!] Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}

	if (pcap_supports_any_dev(alldevs)) {
		pthread_mutex_lock(&lock);
		strncpy(pi.ifname[i], "any", MAX_IFACE_NAME - 1);
		pthread_create(&pi.t_info[i], NULL, capture_thread, &i);
		pthread_mutex_unlock(&lock);
		if (wait_for_thread_init(i) < 0) {
			pthread_mutex_lock(&lock);
			t_info = pi.t_info[i];
			pi.dl_type[i] = 0;
			pthread_mutex_unlock(&lock);
			pthread_cancel(t_info);
			pthread_join(t_info, NULL);
		} else {
			i++;
		}
	} else {
		/* Print the list */
		for (d = alldevs; d; d = d->next) {
			//printf("Starting thread for interface %s\n", d->name);
			/* Copy the interface name to the control block */
			pthread_mutex_lock(&lock);
			strncpy(pi.ifname[i], d->name, MAX_IFACE_NAME - 1);
			pthread_create(&pi.t_info[i], NULL, capture_thread, &i);
			pthread_mutex_unlock(&lock);
			if (wait_for_thread_init(i) < 0) {
				pthread_mutex_lock(&lock);
				t_info = pi.t_info[i];
				pi.dl_type[i] = 0;
				pthread_mutex_unlock(&lock);
				pthread_cancel(t_info);
				pthread_join(t_info, NULL);
			} else {
				i++;
			}
			if (i >= MAX_THREADS) break;
		}
	}
	printf("    libpcap: started %d %s to capture data ...\n", i,
				    (i == 1) ? "thread" : "threads");
	pcap_freealldevs(alldevs);
	return i;
}

int main(int argc, char **argv)
{
	struct sockaddr_in sin;
	int sock;
	__u8 num_threads = 0, full_hwaddr = 1;
	__u32 i;
	pthread_t t_info;
	puts("+-------------------------------------------------------------+");
	puts("|                     Knock NAT box tester                    |");
	puts("+-------------------------------------------------------------+");
	puts("| For bugs, questions or annotations contact knock@gnunet.org |");
	puts("+-------------------------------------------------------------+");

	if (argc > 1 && !strcasecmp(argv[1], "--disable-mac")) full_hwaddr = 0;
	if (full_hwaddr) {
		puts("[+] Will transmit ethernet address. Use --disable-mac\n" \
		     "    in order to transmit only the OUI.");
		usleep(2000000);
	}

	if (pthread_mutex_init(&lock, NULL) < 0) {
		perror("[!] Failed to initialize mutex");
		return EXIT_FAILURE;
	}
	puts("[+] Setting up libpcap ...");
	num_threads = pcap_setup();
	if (num_threads <= 0) {
		fprintf(stderr, "[!] No capturing threads could be created");
#if defined __linux__ || defined __ANDROID__
		fprintf(stderr,	", are you root?\n");
#else
		fprintf(stderr,	".\n");
#endif
		return EXIT_FAILURE;
	}
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(SPORT));
	sin.sin_addr.s_addr = inet_addr(SADDR);
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("[!] Failed to create TCP socket");
		goto out2;
	}
	puts("[+] Sending out the probe ...");

	/* Stupid race condition which we cannot fix. -.-"
	 * The capturing thread needs to set the flag which signals that libpcap
	 * is ready before it actually is ready. Let the main thread sleep for
	 * one second and hope that it will work across devices */
	usleep(1000000);
	if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("[!] Failed to connect to server");
		goto out;
	}
	puts("[+] Probe sent. Waiting for signal from libpcap ...");

	/* Get the ethernet address of the default gateway now as the above
	 * connect should have triggered a SYN resulting in a relatively fresh
	 * entry in the ARP table */
	get_gw_hwaddr(full_hwaddr);
	wait_for_pcap_data();
	puts("[+] Data is ready! Sending ...");
	pi.tp.cksum = fletcher((__u8 *)&pi.tp, sizeof(struct tcp_probe));
	if (send(sock, (const void *)&pi.tp, sizeof(struct tcp_probe), 0) < 0) {
		perror("[!] Failed to send TCP data");
		goto out;
	}
	puts("[+] Transmission completed. Thank you for your participation!");
out:
	if (close(sock) < 0) {
		perror("[!] Failed to close the TCP socket");
	}
out2:
	for (i = 0; i < num_threads; i++) {
		pthread_mutex_lock(&lock);
		t_info = pi.t_info[i];
		pthread_mutex_unlock(&lock);
		pthread_cancel(t_info);
#if !defined _WIN64 && !defined _WIN32
		/* Interestingly WinPcap's pcap_loop returns when it receives
		 * the pthread_cancel command. The capture threads thus cleanup
		 * themselves in windows and we need these only on Linux & OSX */
		pthread_join(t_info, NULL);
		pthread_mutex_lock(&lock);
		pcap_close(pi.pcap_handle[i]);
		pthread_mutex_unlock(&lock);
#endif
	}
	pthread_mutex_destroy(&lock);
#if defined _WIN64 || defined _WIN32
	/* Wait for Windows users to press any key before closing the window.
	 * (Magic cmd prompts showing up for a few seconds normally don't mean
	 * anything good on W32 ...) */
	puts("Press any key to close this window ...");
	i = getchar();
#endif
	return 0;
}
