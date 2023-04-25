#include <stdarg.h>

#include "logsys.h"

__u8 curr_loglvl = KNOCK_LOGLEVEL_SLNT;

int log_ext(unsigned char lvl, const char *fmt, const char *file,
						const char *func,
						unsigned int line,
						FILE *out, ...)
{
	va_list args;

	if (lvl > curr_loglvl) return -1;
	if (curr_loglvl == KNOCK_LOGLEVEL_DEBG)
		fprintf(out, KNOCK_DBG_STRING, file, func, line);

	va_start(args, out);
	vfprintf(out, fmt, args);
	va_end(args);

	return 0;
}

void log_set_lvl(int lvl)
{
	printf("setting loglvl to %d\n", lvl);
	curr_loglvl = lvl;
	return;
}
