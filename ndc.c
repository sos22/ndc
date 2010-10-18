/* Stub library which gets injected into the target program, so that
 * we can find certain magic addresses.  Bit of a hack, but easier
 * than doing it properly. */
#include <err.h>
#include <errno.h>
#include <link.h>
#include <stdlib.h>
#include <unistd.h>

static long
my_strtol(const char *start, int *error)
{
	long r;
	char *e;

	errno = 0;
	r = strtol(start, &e, 10);
	if (errno == ERANGE || e == start || *e != 0) {
		*error = 1;
		return -1;
	} else {
		*error = 0;
		return r;
	}
}

static int
get_env_int(const char *name)
{
	char *var;
	long val;
	int err;

	var = getenv(name);
	if (!var)
		errx(1, "%s not set", name);
	val = my_strtol(var, &err);
	if (err || val != (int)val)
		errx(1, "%s not a valid integer", name);
	return val;
}

static void ndc_main(void) __attribute__((constructor));
static void
ndc_main()
{
	int to_master_fd;
	int from_master_fd;
	int buf;

	to_master_fd = get_env_int("_NDC_to_master");
	from_master_fd = get_env_int("_NDC_from_master");

	/* Tell master where the magic linker breakpoint is */
	write(to_master_fd, &_r_debug.r_brk, sizeof(_r_debug.r_brk));
	close(to_master_fd);
	/* Wait for master to release us.  This should always fail,
	   we're just waiting for the master to call close() */
	read(from_master_fd, &buf, sizeof(buf));
	close(from_master_fd);

	/* Put everything back to how it was */
	if (getenv("_NDC_ld_preload"))
		setenv("LD_PRELOAD", getenv("_NDC_ld_preload"), 1);
	else
		unsetenv("LD_PRELOAD");
	unsetenv("_NDC_to_master");
	unsetenv("_NDC_from_master");
	unsetenv("_NFC_ld_preload");
}


