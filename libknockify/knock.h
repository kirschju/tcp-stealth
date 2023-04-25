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
#ifndef _KNOCK_H
#define _KNOCK_H

#include <sys/types.h>
#include <sys/socket.h>

#include "list.h"

/*
 * We support integrity checking up to 1024 bits. Theoretically, this value can
 * be chosen arbitrarily but the kernel side currently only supports integrity
 * checking on the FIRST data segment. Decrease this value if you expect
 * packet segmentation to happen
 */
#define KNOCK_INT_MAX_LEN		128

#define KNOCK_SOCKET_TYPE_UNSPEC	0
#define KNOCK_SOCKET_TYPE_CLIENT	1
#define KNOCK_SOCKET_TYPE_SERVER	2

int knock_set_secret(char *);
int knock_set_int_len(int);
int knock_set_client_socket(int, const struct sockaddr *, socklen_t addrlen);
int knock_set_server_socket(int);
unsigned int knock_get_int_len(void);
int knock_add_new_socket(int);
int knock_uses_fd(int);
int knock_is_connect_pending(int);
int knock_is_connect_executed(int);
int knock_queue_data(int, const void *, size_t, int);
int knock_flush_data(int);

struct knock_send_parms {
	void *buf;
	size_t len;
	int flags;
};

struct knock_fd {
	/* 
	 * Happily borrowed from the kernel :) ported to userspace by Hareesh
	 * Nagarajan http://www.cs.uic.edu/~hnagaraj/articles/linked-list/
	 */
	struct list_head list_member;

	/* fd of the knockified socket */
	int fd;
	/* used to mark a socket to be a client or server socket */
	unsigned char socket_type;
	/* number of bytes that should be integrity checked, 0 means off */
	unsigned int int_len;
	/* set to 1 if a connect was delayed (needed for integrity checking) */
	unsigned char connect_delayed;
	/* store connection parameters for later connect */
	struct sockaddr delayed_addr;
	socklen_t delayed_addrlen;
	/* we buffer at most KNOCK_MAX_INT_LEN many calls to send or sendmsg */
	struct knock_send_parms send_parms[KNOCK_INT_MAX_LEN];
	/* kepps track how many messages are in the queue */
	unsigned int queued_msgs;
};

#endif
