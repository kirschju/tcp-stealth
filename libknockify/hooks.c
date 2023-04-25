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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <asm/types.h>

#define __USE_GNU
#include <dlfcn.h>

#include "startup.h"
#include "logsys.h"
#include "hooks.h"
#include "knock.h"

/* Emulate write by calling send(fd, buf, count, 0) */
#define EMULATE_WRITE

struct hooked_libc_functions hooks = { 0 };

void *get_libc_address(char *symname)
{
	void *sym;
	const char *err;

	log_msg(KNOCK_LOGLEVEL_VERB, "Resolving symbol %s ...\n", symname);

	sym = dlsym(RTLD_NEXT, symname);
	err = dlerror();

	if (err) {
		log_err(KNOCK_LOGLEVEL_NORM, "Failed to get address " \
					     "of symbol %s: %s\n",
					     symname, err);
		return NULL;
	}

	return sym;
}

int init_hooks()
{
	hooks.socket	 = get_libc_address("socket");
	hooks.connect	 = get_libc_address("connect");
	hooks.listen	 = get_libc_address("listen");
	hooks.write	 = get_libc_address("write");
	hooks.send	 = get_libc_address("send");
	hooks.sendto	 = get_libc_address("sendto");
	hooks.sendmsg	 = get_libc_address("sendmsg");
	hooks.getsockopt = get_libc_address("getsockopt");
	hooks.close	 = get_libc_address("close");
	hooks.epoll_wait = get_libc_address("epoll_wait");
	hooks.select	 = get_libc_address("select");

	/* There needs to be at least the socket() libc-call and at least one
	 * of either connect or listen */
	if (!hooks.connect || !hooks.listen || !hooks.socket) goto fail;

	log_msg(KNOCK_LOGLEVEL_VERB, "All dynamic symbols could be resolved.\n");
	return 0;
fail:
	log_err(KNOCK_LOGLEVEL_VERB, "At least one crucial dynamic import is " \
		"missing in the binary you're trying to LD_PRELOAD.\n");
	return -1;
}

ssize_t write(int fd, const void *buf, size_t count)
{
#ifdef EMULATE_WRITE
	return send(fd, buf, count, 0);
#else
	int res;

	if (knock_uses_fd(fd) && knock_get_int_len()) {
		if (!buf) {
			errno = EINVAL;
			return -1;
		}
		if (!knock_is_connect_pending(fd) &&
		    !knock_is_connect_executed(fd)) {
			errno = ENOTCONN;
			return -1;
		}
		if (knock_queue_data(fd, buf, count, 0)) {
			errno = ENOBUFS;
			return -1;
		}
		if (knock_has_enough_data(fd)) {
			if (knock_connect(fd)) {
				if (errno != EINPROGRESS) {
					errno = ECONNRESET;
					return -1;
				}
			}
			log_msg(KNOCK_LOGLEVEL_VERB,
				"SUCCESS on fd %d!\n", fd);
			knock_flush_data(fd);
			/* Knockification succeeded. The communication can
			 * continue as usual.
			 */
			knock_remove_socket(fd);
		}
		return count;

	}

	res = hooks.write(fd, buf, count);
	log_msg(KNOCK_LOGLEVEL_VERB, "write(%d, %p, %u) = %d\n",
				     fd, buf, count, res);

	return res;
#endif

}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	int res;

	if (knock_uses_fd(sockfd) && knock_get_int_len()) {
		if (!buf) {
			errno = EINVAL;
			return -1;
		}
		if (!knock_is_connect_pending(sockfd) &&
		    !knock_is_connect_executed(sockfd)) {
			errno = ENOTCONN;
			return -1;
		}
		if (knock_queue_data(sockfd, buf, len, flags)) {
			errno = ENOBUFS;
			return -1;
		}
		if (knock_has_enough_data(sockfd)) {
			if (knock_connect(sockfd)) {
				if (errno != EINPROGRESS) {
					errno = ECONNRESET;
					return -1;
				}
			}
			/* TODO: In case of non-blocking I/O we cannot be sure
			 * that the connect call did succeed.*/
			log_msg(KNOCK_LOGLEVEL_VERB,
				"SUCCESS on fd %d!\n", sockfd);
			knock_flush_data(sockfd);
			/* Knockification succeeded. The communication can
			 * continue. */
			knock_remove_socket(sockfd);
		}
		return len;

	}

	res = hooks.send(sockfd, buf, len, flags);
	log_msg(KNOCK_LOGLEVEL_VERB, "send(%d, %p, %u, %d) = %d\n",
				     sockfd, buf, len, flags, res);

	return res;

}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen)
{
	int res;

	/* If the socket should be Knockified with integrity checking,
	 * try to reduce the sendto to a send (see manpage of send(to) */
	if (knock_uses_fd(sockfd) && knock_get_int_len()) {
	   	if (knock_is_connect_pending(sockfd)) {
			/* See manpage of sendto */
			if (dest_addr || addrlen) {
				errno = EISCONN;
				return -1;
			}
			/* Emulate sendto() using send() */
			return send(sockfd, buf, len, flags);
		} else {
			/* See manpage of sendto */
			errno = ENOTCONN;
			return -1;
		}
	}


	res = hooks.sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	log_msg(KNOCK_LOGLEVEL_VERB, "sendto(%d, %p, %u, %d, %p, %u) = %d\n",
				     		     sockfd, buf, len, flags,
						     dest_addr, addrlen, res);

	return res;

}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	int res;

	/* TODO: Missing implementation */
	/* We just hope that the application specifies enough payload data such
	 * that we can just do all of the needed setsockopt calls at once. If it
	 * doesn't, and payload integrity is requested, we silently do not
	 * Knockify for now. */
	if (knock_uses_fd(sockfd)) {
		if (knock_get_int_len()) {

		}
	}

	res = hooks.sendmsg(sockfd, msg, flags);
	log_msg(KNOCK_LOGLEVEL_VERB, "sendto(%d, %p, %d) = %d\n",
				     sockfd, msg, flags, res);

	return res;

}

int listen(int sockfd, int backlog)
{
	int res;


	if (knock_uses_fd(sockfd)) {
		/* Enables integrity protection as indicated by the config */
		if (knock_set_server_socket(sockfd)) {
			errno = EOPNOTSUPP;
			return -1;
		}
	}

	res = hooks.listen(sockfd, backlog);
	log_msg(KNOCK_LOGLEVEL_VERB, "listen(%d, %d) = %d\n",
				       sockfd, backlog, res);

	return res;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct knock_fd *kfd;

	/* Notify the application of a pending connect */
	if (knock_uses_fd(sockfd) && knock_is_connect_pending(sockfd)) {
		errno = EISCONN;
		return -1;
	}
	log_msg(KNOCK_LOGLEVEL_DEBG, "Queueing a connect.\n");

	/* If the socket should be Knockified with integrity checking,
	 * we need to delay the connect and wait for the actual data */
	if (knock_uses_fd(sockfd) &&
	    /* knock_set_client_socket returns 0 if a delay is needed */
	    !knock_set_client_socket(sockfd, addr, addrlen))
		return 0;


	int res = hooks.connect(sockfd, addr, addrlen);
	log_msg(KNOCK_LOGLEVEL_VERB, "connect(%d, %p, %d) = %d\n",
				      sockfd, addr, addrlen, res);

	return res;

}

int socket(int domain, int type, int protocol)
{
	int res = hooks.socket(domain, type, protocol);
	log_msg(KNOCK_LOGLEVEL_VERB, "socket(%d, %d, %d) = %d\n", domain,
						    type, protocol, res);

	/* If the socket call did not succeed return immediately */
	if (res == -1) return res;

	/* Pick the sockets to be knockified as restrictively as possible. */
	/* TODO: Bitmask 0x0f is not very portable (I assume). */
	/* TODO: Linux defines AF_INET as PF_INET, not sure about other *nix */
	if ((domain == PF_INET || domain == PF_INET6) &&
	    (type & 0x0f) == SOCK_STREAM &&
	    protocol == IPPROTO_TCP) {
		log_msg(KNOCK_LOGLEVEL_DEBG, "Adding new socket %d.\n", res);
		if (knock_add_new_socket(res)) {
			/* Maybe better to return EINVAL? */
			errno = EPROTONOSUPPORT;
			return -1;
		}
		log_msg(KNOCK_LOGLEVEL_VERB, "Knockified.\n");

	}
	return res;
}

int getsockopt(int sockfd, int level, int optname,
	       void *optval, socklen_t *optlen)
{
	int res;

	if (knock_uses_fd(sockfd) &&
	    (level == SOL_SOCKET) &&
	    (optname == SO_ERROR) &&
	    (*optlen == 4)) {
		log_msg(KNOCK_LOGLEVEL_DEBG,
			"Patching in a 0 errcode for getsockopt on socket %d.\n",
			sockfd);
		*(int *)optval = 0;
		return 0;
	}

	res = hooks.getsockopt(sockfd, level, optname, optval, optlen);
	return res;
}

int close(int fd)
{
	if (knock_uses_fd(fd))
		knock_remove_socket(fd);

	int res = hooks.close(fd);
	log_msg(KNOCK_LOGLEVEL_VERB, "close(%d) = %d\n", fd, res);

	return res;

}

int epoll_wait(int epfd, struct epoll_event *events,
	       int maxevents, int timeout)
{
	int res;
	int i;

	res = hooks.epoll_wait(epfd, events, maxevents, timeout);

	for (i = 0; i < res; i++) {
		if (knock_uses_fd(*(int *)(events[i].data.ptr)) &&
		    knock_is_connect_pending(*(int *)events[i].data.ptr)) {
			/* Signal that the fd is ready to be written */
			events[i].events = EPOLLOUT;
			log_msg(KNOCK_LOGLEVEL_VERB, "patched epoll_wait\n");
		}
	}

	return res;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	   fd_set *exceptfds, struct timeval *timeout)
{
	int res;
	int i;

	res = hooks.select(nfds, readfds, writefds, exceptfds, timeout);

	for (i = 0; i < nfds; i++) {
		if (knock_uses_fd(i) &&
		    (FD_ISSET(i, readfds) ||
		    FD_ISSET(i, writefds)) &&
		    knock_is_connect_pending(i)) {
			/* Signal that the fd is ready to be written */
			if (writefds) FD_SET(i, writefds);
			if (readfds) FD_CLR(i, readfds);
		}
	}

	return res;
}
