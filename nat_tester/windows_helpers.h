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
 */
#define PTW32_STATIC_LIB
#include <pthread.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Iphlpapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "pthreadVC2.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

typedef unsigned __int8		__u8;
typedef unsigned __int16	__u16;
typedef unsigned __int32	__u32;

#define strncasecmp	_strnicmp
#define strcasecmp	_stricmp
#define close		closesocket

struct ip {
	unsigned int ip_hl:4;
	unsigned int ip_v:4;
	u_int8_t ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_p;
	u_short ip_sum;
	struct in_addr ip_src, ip_dst;
};

struct tcphdr
{
	__u16 th_sport;
	__u16 th_dport;
	__u32 th_seq;
	__u32 th_ack;
	__u8  th_x2:4;
	__u8  th_off:4;
	__u8  th_flags;
	__u16 th_win;
	__u16 th_sum;
	__u16 th_urp;
};

#define TCPOPT_NOP		0x01
#define TCPOPT_TIMESTAMP	0x08
#define TCPOLEN_TIMESTAMP	0x0a
#define PCAP_NETMASK_UNKNOWN	0xffffffff

void usleep(int waitTime) {
    __int64 time1 = 0, time2 = 0, freq = 0;

    QueryPerformanceCounter((LARGE_INTEGER *) &time1);
    QueryPerformanceFrequency((LARGE_INTEGER *)&freq);

    do {
	    QueryPerformanceCounter((LARGE_INTEGER *) &time2);
    } while((time2-time1) < waitTime);
}
