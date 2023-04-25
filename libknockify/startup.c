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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#define __USE_GNU
#include <stdlib.h>

#include "startup.h"
#include "logsys.h"

/* Compile with -DOLD_GETENV if gcc complains */
#ifdef OLD_GETENV
#define secure_getenv	__secure_getenv
#endif

/* TODO: This is not portable at all, fix */
const char elf_interpreter[] __attribute__((section(".interp"))) =
	"/lib64/ld-linux-x86-64.so.2";

int init_config(void)
{
	FILE *f;
	char *line = NULL;
	size_t linelen = 0;
	size_t read = 0;
	char *end;
	int res = -1;
	int tmp;
	struct stat sbuf;

	char confpath[MAX_CONF_PATH_LEN];
	char opt_name[MAX_CONF_PATH_LEN];
	char opt_val[MAX_CONF_PATH_LEN];

	/* TODO: Assumes a shell that sets ${HOME} */
	snprintf(confpath, MAX_CONF_PATH_LEN, "%s/%s",
				secure_getenv("HOME"),
				KNOCK_CONFIG_FILE);

	stat(confpath, &sbuf);
	if (sbuf.st_mode & 07) {
		log_err(KNOCK_LOGLEVEL_NORM,
			"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" \
			"@ WARNING: World accessible .knockrc file found! @\n" \
			"@ Change permissions to at least 660 to continue @\n" \
			"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		return -1;
	}

	if (access(confpath, R_OK)) {
		log_err(KNOCK_LOGLEVEL_VERB,
			"Could not access config file %s: %s.\n",
			confpath,
			strerror(errno));
		return -1;
	}
	f = fopen(confpath, "r");
	if (!f) return -1;

	while (read = getline(&line, &linelen, f) != -1) {
		if (sscanf(line, "%[A-Za-z_]=%s\n", opt_name, opt_val) == 2) {
			if (!strcmp(KNOCK_LOGLEVEL_ENV_NAME, opt_name)) {
				tmp = strtol(opt_val, &end, 10);
				if (end != opt_val) log_set_lvl(tmp);
			} else if (!strcmp(KNOCK_INT_ENV_NAME, opt_name)) {
				tmp = strtol(opt_val, &end, 10);
				if (end != opt_val) knock_set_int_len(tmp);
			} else if (!strcmp(KNOCK_SECRET_ENV_NAME, opt_name)) {
				if (!knock_set_secret(opt_val)) res = 0;
			}
		}
	}

	free(line);
	fclose(f);
	return res;

}

int init_output(void)
{
	const char *knock_loglvl;
	char *end;
	long tmp;

	knock_loglvl = secure_getenv(KNOCK_LOGLEVEL_ENV_NAME);
	if (!knock_loglvl) return -1;

	tmp = strtol(knock_loglvl, &end, 10);
	if (end != knock_loglvl) log_set_lvl(tmp);
	
	return 0;
}

int init_environment(void)
{
	const char *knock_secret;
	const char *knock_int_len;

	knock_secret = secure_getenv(KNOCK_SECRET_ENV_NAME);
	if (!knock_secret) return -1;

	if (knock_set_secret(knock_secret)) {
		log_err(KNOCK_LOGLEVEL_NORM,
			"Failed to set secret. Aborting ...\n");
		return -1;
	}

	knock_int_len = secure_getenv(KNOCK_INT_ENV_NAME);
	if (!knock_int_len) return 0;

	if (knock_set_int_len(atoi(knock_int_len))) {
		log_err(KNOCK_LOGLEVEL_VERB,
			"Failed to set integrity len.\n");
		return 0;
	}
	

	return 0;
}

void __attribute__ ((constructor)) startup(void)
{
	init_output();
	log_msg(KNOCK_LOGLEVEL_VERB, "Initializing environment ...\n");
	if (init_config() == -1 && init_environment() == -1) exit(-1);
	log_msg(KNOCK_LOGLEVEL_VERB, "Initializing hooks ...\n");
	init_hooks();
}

void print_info(void)
{
	printf("This is a shared library to be used in your LD_PRELOAD path.\n");
	_exit(0);
}
