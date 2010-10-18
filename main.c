#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* We have a worker process for each process to which we're currently
   attached, and that process is responsible for issuing ptrace
   commands etc.  This is a lot easier. */
struct process {
	int to_worker_fd;
	int from_worker_fd;
};

struct driver {
	int to_driver_fd;
	int from_driver_fd;
};

static char *
fdgetline(int fd)
{
	char *res;
	ssize_t x;
	ssize_t res_size;
	ssize_t l;

	res = malloc(16);
	res_size = 16;
	x = 0;
	res[x] = ' ';

	while (1) {
		l = read(fd, res + x, 1);
		if (l == 0 || res[x] == '\n') {
			res[x] = 0;
			return res;
		}
		if (l < 0) {
			free(res);
			return NULL;
		}
		x++;
		if (x == res_size) {
			res_size *= 2;
			res = realloc(res, res_size * 2);
		}
	}
}

static void
worker_vmsg(struct driver *d, const char *fmt, va_list args)
{
	FILE *f = fdopen(d->to_driver_fd, "w");
	vfprintf(f, fmt, args);
	fclose(f);
}

static void
worker_msg(struct driver *d, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	worker_vmsg(d, fmt, args);
	va_end(args);
}

static void
worker_err(struct driver *d, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	worker_vmsg(d, fmt, args);
	va_end(args);
	worker_msg(d, "%s\n", strerror(errno));
	_exit(1);
}

static void
worker_errx(struct driver *d, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	worker_vmsg(d, fmt, args);
	va_end(args);
	worker_msg(d, "\n");
	_exit(1);
}

static struct process *
ptrace_spawn(const char *fname, char *const argv[], char *const env[])
{
	int to_worker[2], from_worker[2];
	struct process *p;
	pid_t worker_pid;
	char *resp;

	if (pipe2(to_worker, O_CLOEXEC) < 0)
		return NULL;
	if (pipe2(from_worker, O_CLOEXEC) < 0) {
		close(to_worker[0]);
		close(to_worker[1]);
		return NULL;
	}

	worker_pid = fork();
	if (worker_pid == (pid_t)-1) {
		close(to_worker[0]);
		close(to_worker[1]);
		close(from_worker[0]);
		close(from_worker[1]);
		return NULL;
	}
	if (worker_pid == 0) {
		/* We are the worker. */
		struct driver *d = calloc(sizeof(*d), 1);
		pid_t child;
		int status;

		d->to_driver_fd = from_worker[1];
		d->from_driver_fd = to_worker[0];
		close(from_worker[0]);
		close(to_worker[1]);

		child = fork();
		if (child == (pid_t)-1)
			worker_err(d, "fork()");
		if (child == 0) {
			ptrace(PTRACE_TRACEME);
			execve(fname, argv, env);
			_exit(1);
		}
		if (waitpid(child, &status, 0) != child)
			worker_err(d, "waitpid()");
		if (!WIFSTOPPED(status) ||
		    WSTOPSIG(status) != SIGTRAP)
			worker_errx(d, "child had strange status %x", status);
		if (ptrace(PTRACE_SETOPTIONS, child, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC) < 0)
			worker_err(d, "setting ptrace options");
		if (ptrace(PTRACE_SYSCALL, child) < 0)
			worker_err(d, "getting child out of exec syscall");
		worker_msg(d, "OK\n");
		worker_loop(d, child);
	}

	close(from_worker[1]);
	close(to_worker[0]);

	resp = fdgetline(p->from_worker_fd);
	if (!resp ||
	    strcmp(resp, "OK")) {
		if (resp)
			warnx("%s", resp);
		free(resp);
		kill(worker_pid, SIGKILL);
		close(to_worker[1]);
		close(from_worker[0]);
		return NULL;
	}

	p = calloc(sizeof(*p), 1);
	p->to_worker_fd = to_worker[1];
	p->from_worker_fd = from_worker[0];
	return p;
}

int
main(int argc, char *argv[])
{
	struct process *p;

	p = ptrace_spawn(argv[1], argv + 2, environ);

	proxy(p);

	return 0;
}
