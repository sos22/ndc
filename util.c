/* Various utility and debug functions */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ndc.h"

#ifndef NDEBUG
static void
sanity_check_bp(const struct breakpoint *bp)
{
	if (bp->next)
		assert(bp->next->prev == bp);
	if (bp->prev)
		assert(bp->prev->next == bp);
	if (bp->next_lo) {
		assert(bp->next_lo->prev_lo == bp);
		assert(bp->lo);
	}
	if (bp->prev_lo) {
		assert(bp->prev_lo->next_lo == bp);
		assert(bp->lo);
	} else if (bp->lo)
		assert(bp->lo->head_bp == bp);
}

void
sanity_check_lo(const struct loaded_object *lo)
{
	const struct breakpoint *bp;
	assert(lo->name);
	assert(strlen(lo->name));
	for (bp = lo->head_bp; bp; bp = bp->next_lo) {
		assert(bp->lo == lo);
		sanity_check_bp(bp);
	}
}
#else /* !NDEBUG */
void
sanity_check_lo(const struct loaded_object *lo)
{
}
#endif /* NDEBUG */

int
tgkill(int tgid, int tid, int sig)
{
	return syscall(__NR_tgkill, tgid, tid, sig);
}

void
my_setenv(const char *name, const char *fmt, ...)
{
	va_list args;
	char *m;
	va_start(args, fmt);
	vasprintf(&m, fmt, args);
	va_end(args);
	setenv(name, m, 1);
	free(m);
}
