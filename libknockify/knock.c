/*
 *  This file is part of libknockify.
 *
 *  libknockify is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libknockify is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with libknockify.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>

#include <netinet/in.h>

#include "knock.h"
#include "logsys.h"
#include "startup.h"
#include "list.h"
#include "hooks.h"

#define KNOCK_SECRET_SIZE 		64
unsigned char knock_secret[KNOCK_SECRET_SIZE] = { 0 };
/* Default length for integrity checks is 0 ( == disabled) */
#define KNOCK_DEF_INT_LEN 		0
unsigned int knock_int_len = KNOCK_DEF_INT_LEN;

#define MIN(A, B)			((A < B) ? A : B)
#define MAX(A, B)			((A > B) ? A : B)

/* Current (kernel > 3.10) sockopt numbers for Knock */
#define	KNOCK_TCP_STEALTH		26
#define KNOCK_TCP_INTEGRITY		27
#define KNOCK_TCP_INTEGRITY_LEN		28

/* To signal that connect() has already been called on the socket */
#define KNOCK_CONNECT_DELAYED		1
#define KNOCK_CONNECT_EXECUTED		2

int __set_secret_raw(unsigned char *secret, size_t len)
{
	printk("%s\n", secret);
	if (len > KNOCK_SECRET_SIZE) {
		log_msg(KNOCK_LOGLEVEL_NORM,
			"Warning: Truncating secret to %d bytes.",
			KNOCK_SECRET_SIZE);
		len = KNOCK_SECRET_SIZE;
	}
	memset(knock_secret, 0x00, KNOCK_SECRET_SIZE);
	memcpy(knock_secret, secret, len);
	return 0;
}

int __set_secret_file(unsigned char *filename)
{
	FILE *f;
	size_t len;

	if (access(filename, R_OK)) {
		log_err(KNOCK_LOGLEVEL_NORM,
			"Failed to access file %s: %s.\n",
			filename, strerror(errno));
		return -1;
	}

	memset(knock_secret, 0x00, KNOCK_SECRET_SIZE);

	f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (len > KNOCK_SECRET_SIZE) {
		log_msg(KNOCK_LOGLEVEL_NORM,
			"Warning: Truncating secret to %d bytes.\n",
			KNOCK_SECRET_SIZE);
		len = KNOCK_SECRET_SIZE;
	}
	len = fread(knock_secret, sizeof(unsigned char), len, f);
	fclose(f);

	if (!len) {
		log_msg(KNOCK_LOGLEVEL_NORM,
			"Failed to read secret from file.\n");
		return -1;
	}

	return 0;
}

int __collect_payload(struct knock_fd *kfd, void *payload, unsigned int len)
{
	unsigned int l;
	unsigned int i = 0;

	while (len) {
		l = MIN(len, kfd->send_parms[i].len);
		memcpy(payload, kfd->send_parms[i].buf, l);
		len -= l;
		i++;
	}

	return 0;

}

int knock_set_secret(char *secstr)
{
	FILE *f;
	unsigned char dat[KNOCK_SECRET_SIZE];
	int i = 0;
	size_t len;

	if (!secstr || !strlen(secstr)) {
		log_err(KNOCK_LOGLEVEL_NORM,
			"No secret specified. Use variable %s.\n",
			KNOCK_SECRET_ENV_NAME);
		return -1;
	}

	if (strlen(secstr) < 3) {
		log_err(KNOCK_LOGLEVEL_NORM, "Secret too short.\n");
		return -1;
	}

	/*
	 * Parse secret. Knock supports the following formats:
	 *
	 * plain string (default, no prefix)
	 * r:len: raw bytes
	 * h: hexstring
	 * f: read file contents
	 */

	if (secstr[1] != ':') {
		return __set_secret_raw(secstr, strlen(secstr));
	}

	switch (secstr[0]) {
	case 'h':
		log_msg(KNOCK_LOGLEVEL_VERB, "Read secret as hex string.\n");
		while (sscanf(&secstr[2 + i], "%02hhx", &dat[i]) == 1 &&
		       i < strlen(secstr) - 2 &&
		       i < KNOCK_SECRET_SIZE) i++;
		return __set_secret_raw(secstr, (size_t)i);
	break;
	case 'f':
		log_msg(KNOCK_LOGLEVEL_VERB, "Read secret from file.\n");
		return __set_secret_file(&secstr[2]);
	break;
	case 'r':
		log_msg(KNOCK_LOGLEVEL_VERB, "Read secret as raw bytes.\n");
		while (secstr[2 + i] != ':') i++;
		secstr[2 + i] = '\0';
		len = atoi(&secstr[2]);
		return __set_secret_raw(&secstr[2 + i + 1], len);
	break;
	default:
		log_msg(KNOCK_LOGLEVEL_VERB, "Read secret as plain string.\n");
		return __set_secret_raw(secstr, strlen(secstr));
	break;
	}

	return 0;
}

/*
 * Enable Knock's integrity checking by specifying the number of bytes to
 * be hashed
 * arg0: number of bytes of the first packet to be checked
 * retn: 0
 */
int knock_set_int_len(int int_len)
{

	log_msg(KNOCK_LOGLEVEL_VERB, "Setting integrity check len to %d bytes.\n",
								       int_len);
	/* Integrity length is bound by 0 and KNOCK_INT_MAX_LEN */
	knock_int_len = MIN(MAX(0, int_len), KNOCK_INT_MAX_LEN);

	return 0;
}

/*
 * Return the default number of bytes which should be integrity-checked
 * retn: knock_int_len
 */
unsigned int knock_get_int_len(void)
{
	return knock_int_len;
}

/*
 * Enable Knock for the specified socket and add the socket to the list
 * to keep track of knockified fds
 * arg0: fd of the new Knock socket
 * retn: 0 if the socket has been knockified, -1 otherwise
 */
int knock_add_new_socket(int fd)
{

	/* Knockify the socket */
	if (setsockopt(fd, IPPROTO_TCP, KNOCK_TCP_STEALTH, knock_secret,
						     KNOCK_SECRET_SIZE)) {
		log_err(KNOCK_LOGLEVEL_NORM, "Critical: setsockopt() failed " \
					     "on fd %d. Make sure that your " \
					     "kernel supports Knock.\n", fd);
		log_err(KNOCK_LOGLEVEL_NORM, "Could not enable " \
					     "authentication on fd %d: %s.\n",
					     fd, strerror(errno));
		return -1;
	}
	log_msg(KNOCK_LOGLEVEL_NORM, "Socket %d will be Knockified.\n", fd);

	/* Register new fd */
	return list_add_knock_fd(fd);
}

/*
 * Remove knockify information for a specific socket
 * arg0: fd of the corresponding socket to be removed
 * retn: 0 if knockify information has been removed, -1 otherwise
 */
int knock_remove_socket(int fd)
{
	if (!knock_uses_fd(fd)) return -1;
	log_msg(KNOCK_LOGLEVEL_NORM, "Un-Knockifing socket %d ...\n", fd);
	return list_del_knock_fd(fd);
}

/*
 * Check if the specified socket is knockified
 * arg0: fd of the corresponding socket to be checked
 * retn: 1 if socket is knockified, 0 otherwise
 */
int knock_uses_fd(int fd)
{
	if (list_find_knock_fd(fd)) return 1;
	return 0;
}

/*
 * Check if a connect is pending
 * arg0: fd of the corresponding socket which is to be checked
 * retn: 1 if connect is pending, 0 otherwise
 */
int knock_is_connect_pending(int fd)
{
	struct knock_fd *kfd;

	if (kfd = list_find_knock_fd(fd))
		return (kfd->connect_delayed == KNOCK_CONNECT_DELAYED);

	return 0;
}

/*
 * Check if a delayed connect had been executed
 * arg0: fd of the corresponding socket which is to be checked
 * retn: 1 if connect was executed, 0 otherwise
 */
int knock_is_connect_executed(int fd)
{
	struct knock_fd *kfd;

	if (kfd = list_find_knock_fd(fd))
		return (kfd->connect_delayed == KNOCK_CONNECT_EXECUTED);

	return 0;
}

/*
 * Mark the socket to be a server Knock socket
 * arg0: fd of the socket
 * retn: 0 on success, -1 otherwise
 */
int knock_set_server_socket(int fd)
{
	struct knock_fd *kfd = list_find_knock_fd(fd);

	if (knock_int_len == 0) return 0;
	log_msg(KNOCK_LOGLEVEL_DEBG, "Socket %d has type %d\n", fd, kfd->socket_type);
	if (knock_int_len > 0 && kfd &&
	    kfd->socket_type == KNOCK_SOCKET_TYPE_UNSPEC &&
	    !setsockopt(fd, IPPROTO_TCP, KNOCK_TCP_INTEGRITY_LEN,
					&knock_int_len,
					sizeof(knock_int_len))) {
		kfd->socket_type = KNOCK_SOCKET_TYPE_SERVER;
		log_msg(KNOCK_LOGLEVEL_DEBG, "Socket %d marked as server.\n",
									 fd);
		return 0;
	}

	return -1;
}

/*
 * Mark the socket to be a client Knock socket and decide whether to delay
 * a connect on this socket.
 * arg0: fd of the socket
 * retn: 0 if connect should be delayed, -1 otherwise
 */
int knock_set_client_socket(int fd, const struct sockaddr *addr,
			    socklen_t addrlen)
{
	struct knock_fd *kfd;
	socklen_t len;
	kfd = list_find_knock_fd(fd);

	log_msg(KNOCK_LOGLEVEL_DEBG, "Checking if a delay is needed ...\n");
	if (knock_int_len > 0 && kfd &&
	    kfd->socket_type == KNOCK_SOCKET_TYPE_UNSPEC) {
		kfd->socket_type = KNOCK_SOCKET_TYPE_CLIENT;
		log_msg(KNOCK_LOGLEVEL_VERB, "Delaying connect on socket %d.\n",
									    fd);
		kfd->connect_delayed = KNOCK_CONNECT_DELAYED;
		kfd->int_len = knock_get_int_len();
		len = MIN(addrlen, sizeof(struct sockaddr));
		memcpy(&kfd->delayed_addr, addr, len);
		log_msg(KNOCK_LOGLEVEL_DEBG, "Copied %d bytes from %p to %p.\n",
			len, addr, &kfd->delayed_addr);
		kfd->delayed_addrlen = len;
		log_msg(KNOCK_LOGLEVEL_DEBG, "Socket %d marked as client.\n",
									 fd);
		return 0;
	}

no_delay:
	return -1;
}

/*
 * Copies the data (and metadata) to for sending into a local buffer
 * arg0: fd of the corresponding socket
 * arg1: buffer which holds the data
 * arg2: length of the data buffer
 * arg3: flags to be used in the send() libc call
 * retn: 0 if data was queued successfully, -1 otherwise
 */
int knock_queue_data(int sockfd, const void *buf, size_t len, int flags)
{
	if (!buf || !len) return -1;

	struct knock_fd *kfd;
	struct knock_send_parms *send_parms;

	kfd = list_find_knock_fd(sockfd);

	/* We only buffer user data if integrity checking is activated,
	 * there has been a connect intercepted and the queue isn't full */
	if (knock_int_len && kfd &&
	    kfd->connect_delayed == KNOCK_CONNECT_DELAYED &&
	    kfd->queued_msgs < KNOCK_INT_MAX_LEN) {
		send_parms = &kfd->send_parms[kfd->queued_msgs];
		send_parms->buf = malloc(len);
		if (!send_parms->buf) return -1;
		memcpy(send_parms->buf, buf, len);
		send_parms->len = len;
		send_parms->flags = flags;
		log_msg(KNOCK_LOGLEVEL_DEBG,
			"Queued msg%02x on fd %d, size %d bytes\n",
			kfd->queued_msgs, sockfd, len);
		kfd->queued_msgs++;

		return 0;
	}

	return -1;

}

/*
 * Determine if the buffers corresponding to this socket hold enough data such
 * that the integrity checking in the kernel can succeed.
 * arg0: fd of the corresponding socket
 * retn: 1 if there is enough data, 0 otherwise
 */
int knock_has_enough_data(int fd)
{
	struct knock_fd *kfd;
	int i;
	unsigned int sum = 0;

	kfd = list_find_knock_fd(fd);

	if (knock_int_len && kfd) {
		for (i = 0; i < kfd->queued_msgs; i++)
			sum += kfd->send_parms[i].len;
		log_msg(KNOCK_LOGLEVEL_DEBG,
			"Socket %d currently buffers %d bytes of data.\n",
			fd, sum);
		return (sum >= knock_int_len) ? 1 : 0;
	}

	return 0;
}

int knock_connect(int fd)
{
	struct knock_fd *kfd = list_find_knock_fd(fd);
	unsigned char payload[knock_int_len];

	if (kfd && kfd->connect_delayed && knock_has_enough_data(fd)) {
		__collect_payload(kfd, payload, knock_int_len);
		/* Knockify the socket */
		if (setsockopt(fd, IPPROTO_TCP, KNOCK_TCP_INTEGRITY, payload,
							      knock_int_len)) {
			log_err(KNOCK_LOGLEVEL_NORM,
				"Critical: setsockopt() failed " \
				"on fd %d. Make sure that your " \
				"kernel supports Knock.\n", fd);
			log_err(KNOCK_LOGLEVEL_NORM,
				"Could not enable payload " \
				"integrity on fd %d: %s.\n",
				fd, strerror(errno));
			return -1;
		}
		kfd->connect_delayed = KNOCK_CONNECT_EXECUTED;
		log_msg(KNOCK_LOGLEVEL_DEBG,
			"Socket %d executes the delayed connect ...\n",
			fd);

		return hooks.connect(fd, &kfd->delayed_addr,
				     kfd->delayed_addrlen);
	}

	return -1;
}

int knock_flush_data(int fd)
{
	struct knock_fd *kfd = list_find_knock_fd(fd);
	struct knock_send_parms *parms;
	int i;
	int res = 0;

	if (kfd && kfd->connect_delayed == KNOCK_CONNECT_EXECUTED) {
		log_msg(KNOCK_LOGLEVEL_VERB,
			"Flushing %d queued messages.\n", kfd->queued_msgs);
		for (i = 0; i < kfd->queued_msgs; i++) {
			parms = &kfd->send_parms[i];
			log_msg(KNOCK_LOGLEVEL_DEBG,
				"Socket %d sends out msg%02x, size %u bytes.\n",
				fd, i, parms->len);
			res |= hooks.send(fd, parms->buf, parms->len, parms->flags);
			free(parms->buf);
		}
		log_msg(KNOCK_LOGLEVEL_DEBG, "Result is %d\n", res);
		return res;
	}

	return -1;

}
