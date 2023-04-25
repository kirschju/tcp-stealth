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
#ifndef _HOOK_H
#define _HOOK_H

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/epoll.h>

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#define __USE_GNU
#include <dlfcn.h>

#include "startup.h"
#include "logsys.h"

extern struct hooked_libc_functions {
	int (*socket)(int, int, int);
	int (*connect)(int, const struct sockaddr *, socklen_t);
	int (*listen)(int, int);
	ssize_t (*write)(int, const void *, size_t);
	ssize_t (*send)(int, const void *, size_t, int);
	ssize_t (*sendto)(int, const void *, size_t, int,
			  const struct sockaddr *, socklen_t);
	ssize_t (*sendmsg)(int, const struct msghdr *, int);
	int (*getsockopt)(int, int, int, void *, socklen_t *);
	int (*close)(int);
	int (*epoll_wait)(int, struct epoll_event *, int, int);
	int (*select)(int nfds, fd_set *, fd_set *, fd_set *, struct timeval *);
} hooks;

int init_hooks();

#endif /* defined _HOOK_H */
