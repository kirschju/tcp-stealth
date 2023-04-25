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
#ifndef _LOGSYS_H
#define _LOGSYS_H

#include <stdio.h>
#include <asm/types.h>

#define COL			"\33[30;1m"
#define DEF			"\33[0m"
#define KNOCK_LOG_STRING	"[knock_enable] "
#define KNOCK_DBG_STRING	COL "[knock_enable:%010s:%020s:%03d]" DEF "\n\t"

#define KNOCK_LOGLEVEL_ENV_NAME	"KNOCK_LOGLVL"

#define KNOCK_LOGLEVEL_SLNT	0
#define KNOCK_LOGLEVEL_NORM	1
#define KNOCK_LOGLEVEL_VERB	2
#define KNOCK_LOGLEVEL_DEBG	3

#define log_msg(lvl, fmt, ...) \
	log_ext(lvl, fmt, __FILE__, __func__, __LINE__, stdout, ##__VA_ARGS__)
#define log_err(lvl, fmt, ...) \
	log_ext(lvl, fmt, __FILE__, __func__, __LINE__, stderr, ##__VA_ARGS__)

int init_logsys();
int log_ext(unsigned char lvl, const char *fmt, const char *file,
						const char *func,
						unsigned int line,
						FILE *out, ...);
void log_set_lvl(int);

#endif /* defined _LOGSYS_H */
