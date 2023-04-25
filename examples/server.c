
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/select.h>

#define TCP_STEALTH			26
#define TCP_STEALTH_INTEGRITY_LEN	28

int main(int argc, char **argv)
{

	int sock, client, retval;
	char secret[64] = "secret";
	int payload_len = 4;
	short port = 4242;

	unsigned char buf[512] = { 0 };
	fd_set rfds;

#ifdef IPV6_EXAMPLE
	struct sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;

	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#elif defined IPV4_EXAMPLE
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
	if (sock < 0) {
		printf("socket() failed, %s\n", strerror(errno));
		return 1;
	}

	if (setsockopt(sock, IPPROTO_TCP, TCP_STEALTH, secret, sizeof(secret))) {
		printf("setsockopt() failed, %s\n", strerror(errno));
		return 1;
	}

#ifdef DO_INTEGRITY
	if (setsockopt(sock, IPPROTO_TCP, TCP_STEALTH_INTEGRITY_LEN,
		       &payload_len, sizeof(payload_len))) {
		printf("setsockopt() failed, %s\n", strerror(errno));
		return 1;
	}
#endif

	if (bind(sock, (struct sockaddr*) &addr, sizeof(addr))) {
		printf("bind() failed %s\n", strerror(errno));
		return 1;
	}

	if (listen(sock, 10)) {
		printf("listen() failed, %s\n", strerror(errno));
		return 1;
	}

	client = accept(sock, NULL, 0);
	if (client < 0) {
		printf("accept() failed, %s\n", strerror(errno));
		return 1;
	}

	do {
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(client, &rfds);

		retval = select(((sock > client) ? sock : client) + 1, &rfds,
		       NULL, NULL, NULL);

		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			int len = read(STDIN_FILENO, buf, sizeof(buf));
			send(client, buf, len, 0);
		}
		if (FD_ISSET(client, &rfds)) {
			int len = recv(client, buf, sizeof(buf), 0);
			if (!len) {
				puts("Peer closed connection.");
				break;
			}
			/* Manually zero-terminate the received string :) */
			*(buf + len) = 0;
			printf("%s", buf);
		}

	} while (retval > 0);

	close(sock);

        return 0;
}
