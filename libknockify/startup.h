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
#ifndef _STARTUP_H
#define _STARTUP_H

#define KNOCK_SECRET_ENV_NAME	"KNOCK_SECRET"
#define KNOCK_INT_ENV_NAME	"KNOCK_INTEGRITY_LEN"

/* Relative to user home */
#define KNOCK_CONFIG_FILE	".knockrc"
#define MAX_CONF_PATH_LEN	1024

int init_environment();

#endif /* defined _STARTUP_H */
