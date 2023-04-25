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
#include <malloc.h>
#include <string.h>

#include "list.h"
#include "knock.h"

LIST_HEAD(knock_list_head);

/*
 * Add a struct knock_fd to the list
 * arg0: fd of the socket to be added
 * retn: 0 if successful, -1 otherwise
 */
int list_add_knock_fd(int fd)
{
	/* Don't accept a fd which is already in the list */
	if (list_find_knock_fd(fd)) return 0;

	struct knock_fd *new =
		(struct knock_fd *)malloc(sizeof(struct knock_fd));
	if (!new) return -1;
	memset(new, 0x00, sizeof(struct knock_fd));

	new->socket_type = KNOCK_SOCKET_TYPE_UNSPEC;
	new->fd = fd;

	INIT_LIST_HEAD(&new->list_member);
	list_add(&new->list_member, &knock_list_head);

	return 0;
}

/*
 * Find a struct knock_fd in the list specified by the corresponding socket fd
 * arg0: fd of the socket to be searched
 * retn: a pointer to the corresponding struct knock_fd, NULL otherwise
 */
struct knock_fd *list_find_knock_fd(int fd)
{
	struct list_head *iter;
	struct knock_fd *res;

	__list_for_each(iter, &knock_list_head) {
		res = list_entry(iter, struct knock_fd, list_member);
		if (res->fd == fd) return res;
	}

	return NULL;
}

/*
 * Remove a struct knock_fd from the list and free the memory
 * arg0: fd of the socket to be removed
 * retn: 0 if successful, -1 otherwise
 */
int list_del_knock_fd(int fd)
{
	struct list_head *iter;
	struct knock_fd *res;

	__list_for_each(iter, &knock_list_head) {
		res = list_entry(iter, struct knock_fd, list_member);
		if (res->fd == fd) {
			list_del(&res->list_member);
			free(res);
			return 0;
		}
	}

	return -1;
}
