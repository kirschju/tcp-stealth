#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/select.h>

#define TCP_STEALTH		26
#define TCP_STEALTH_INTEGRITY	27

int main(int argc, char **argv)
{
	int sock, retval;
	char secret[64] = "secret";
	char payload[4] = "1234";
	short port = 4242;

	unsigned char buf[512] = { 0 };
	fd_set rfds;

#ifdef IPV6_EXAMPLE
	struct sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	inet_pton(AF_INET6, "2001:db8::2a:2a", &addr.sin6_addr);

	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#elif defined IPV4_EXAMPLE
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_aton("131.254.14.32", &addr.sin_addr);

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
	if (setsockopt(sock, IPPROTO_TCP, TCP_STEALTH_INTEGRITY, payload,
		       sizeof(payload))) {
		printf("setsockopt() failed, %s\n", strerror(errno));
		return 1;
	}
#endif


	if (connect(sock, (struct sockaddr*) &addr, sizeof(addr))) {
		printf("connect() failed %s\n", strerror(errno));
		return 1;
	}


	do {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(sock, &rfds);

		retval = select(sock + 1, &rfds, NULL, NULL, NULL);

		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			int len = read(STDIN_FILENO, buf, sizeof(buf));
			send(sock, buf, len, 0);
		}
		if (FD_ISSET(sock, &rfds)) {
			int len = recv(sock, buf, sizeof(buf), 0);
			if (!len) {
				puts("Peer closed connection.");
				break;
			}
			/* Manually 0-terminate the string :) */
			*(buf + len) = 0;
			printf("%s", buf);
		}

	} while (retval > 0);

	close(sock);

        return 0;
}
