#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ndc.h"

/* We aim to have one in TARGET_BREAKPOINT_RATION possible breakpoints
   live at any one time */
#define TARGET_BREAKPOINT_RATIO 10

/* Every n seconds, clear all breakpoints and set a new batch. */
#define RESET_BREAKPOINTS_TIMEOUT 1

/* How long to wiat for after we've hit a breakpoint.  In seconds, as
 * a double. */
#define DELAY_WHEN_BREAKPOINT_HIT 0.01

/* Define to turn on lots of extra tracing */
#undef VERY_LOUD

#define PRELOAD_LIB_NAME "/local/scratch/sos22/notdc/ndc.so"
#define PTRACE_OPTIONS (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC)

static const char *target_binary;

static void memory_access_breakpoint(struct thread *p, struct breakpoint *bp, void *ctxt,
				     struct user_regs_struct *urs);

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

static void
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
static void
sanity_check_lo(const struct loaded_object *lo)
{
}
#endif /* NDEBUG */

int
thr_stop_status(const struct thread *thr)
{
	assert(thr->_stop_status != -1);
	return thr->_stop_status;
}

bool
thr_is_stopped(const struct thread *thr)
{
	return thr->_stop_status != -1;
}

void
thr_stopped(struct thread *thr, int status)
{
	assert(status != -1);
	assert(thr->_stop_status == -1);
	thr->_stop_status = status;
}

void
thr_resume(struct thread *thr)
{
	assert(thr->_stop_status != -1);
	thr->_stop_status = -1;
}

int
tgkill(int tgid, int tid, int sig)
{
	return syscall(__NR_tgkill, tgid, tid, sig);
}

/* Invoked as an on_exit handler to do any necessary final cleanup */
static void
kill_child(int ign, void *_child)
{
	struct process *child = _child;
	while (child->head_thread) {
		tgkill(child->tgid, child->head_thread->pid, SIGKILL);
		child->head_thread = child->head_thread->next;
	}
}

static void my_setenv(const char *name, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void
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

static struct process *
spawn_child(const char *path, char *const argv[])
{
	struct process *work;
	struct thread *thr;
	int p1[2], p2[2];

	work = calloc(sizeof(*work), 1);
	thr = calloc(sizeof(*thr), 1);
	work->head_thread = thr;
	work->nr_threads = 1;
	thr->process = work;
	thr->_stop_status = -1;
	if (pipe(p1) < 0 || pipe(p2) < 0)
		err(1, "pipe()");
	work->tgid = thr->pid = fork();
	if (thr->pid < 0)
		err(1, "fork()");
	if (thr->pid == 0) {
		/* We are the child */
		char *ld_preload;

		close(p1[0]);
		close(p2[1]);
		my_setenv("_NDC_to_master", "%d", p1[1]);
		my_setenv("_NDC_from_master", "%d", p2[0]);

		ld_preload = getenv("LD_PRELOAD");
		if (ld_preload)
			my_setenv("_NDC_ld_preload", "%s", ld_preload);
		if (ld_preload && strcmp(ld_preload, ""))
			my_setenv("LD_PRELOAD", "%s:%s", ld_preload, PRELOAD_LIB_NAME);
		else
			my_setenv("LD_PRELOAD", "%s", PRELOAD_LIB_NAME);

		if (ptrace(PTRACE_TRACEME) < 0)
			err(1, "ptrace(PTRACE_TRACEME)");

		execv(path, argv);
		err(1, "exec %s", path);
	}

	/* We are the parent */
	close(p1[1]);
	close(p2[0]);
	work->from_child_fd = p1[0];
	work->to_child_fd = p2[1];

	on_exit(kill_child, work);

	while (!thr_is_stopped(thr))
		if (!receive_ptrace_event(work))
			abort();
	if (!WIFSTOPPED(thr_stop_status(thr)) ||
	    WSTOPSIG(thr_stop_status(thr)) != SIGTRAP)
		errx(1, "strange status %x from waitpid()", thr_stop_status(thr));

	if (ptrace(PTRACE_SETOPTIONS,
		   thr->pid,
		   NULL,
		   PTRACE_OPTIONS) < 0)
		err(1, "ptrace(PTRACE_SETOPTIONS)");

	return work;
}

void
add_mem_access_instr(struct loaded_object *lo, unsigned long addr)
{
#ifdef VERY_LOUD
	printf("Found memory accessing instruction at %#lx\n", addr);
#endif

	if (lo->nr_instrs == lo->nr_instrs_alloced) {
		lo->nr_instrs_alloced *= 3;
		lo->instrs = realloc(lo->instrs, sizeof(lo->instrs[0]) * lo->nr_instrs_alloced);
	}
	lo->instrs[lo->nr_instrs] = addr;
	lo->nr_instrs++;
}

static void
report_race(struct thread *thr1, struct thread *thr2)
{
	struct user_regs_struct urs1, urs2;

	get_regs(thr1, &urs1);
	get_regs(thr2, &urs2);
	printf("Race detected between pid %d RIP %lx and pid %d RIP %lx\n",
	       thr1->pid,
	       urs1.rip,
	       thr2->pid,
	       urs2.rip);
}

static volatile bool
timer_fired;

static void
itimer_handler(int ignore)
{
	timer_fired = true;
}

static void
clear_all_breakpoints(struct thread *thr, struct loaded_object *lo)
{
	while (lo->head_bp)
		unset_breakpoint(thr, lo->head_bp);
}

static void
install_breakpoints(struct thread *thr, struct loaded_object *lo)
{
	unsigned target_nr_breakpoints;
	struct breakpoint *bp;
	unsigned x;
	unsigned long addr;

	target_nr_breakpoints = lo->nr_instrs / TARGET_BREAKPOINT_RATIO;

	sanity_check_lo(lo);
	while (lo->nr_breakpoints < target_nr_breakpoints) {
		x = random() % lo->nr_instrs;
		addr = lo->instrs[x];
		for (bp = lo->head_bp; bp && bp->addr != addr; bp = bp->next_lo)
			;
		if (bp)
			continue;
		bp = set_breakpoint(thr, lo->instrs[x], lo, memory_access_breakpoint, lo);
		if (lo->head_bp)
			lo->head_bp->prev_lo = bp;
		bp->next_lo = lo->head_bp;
		lo->head_bp = bp;
		lo->nr_breakpoints++;
	}
	sanity_check_lo(lo);
}

static void
memory_access_breakpoint(struct thread *p, struct breakpoint *bp, void *ctxt,
			 struct user_regs_struct *urs)
{
	unsigned char instr[16];
	unsigned prefixes;
	struct instr_template it;
	unsigned long modrm_addr;
	struct watchpoint *wp;
	struct itimerval itimer;

	assert(bp->lo);
	sanity_check_lo(bp->lo);

	/* No longer need this breakpoint. */
	unset_breakpoint(p, bp);
	set_regs(p, urs);

	if (p->process->nr_threads == 1) {
		install_breakpoints(p, bp->lo);
		return;
	}

	/* Set to contain a bunch of nops... */
	memset(instr, 0x90, sizeof(instr));
	/* Then grab as much of the actual isntruction as possible,
	 * unless we get a page fault.  Should really do something
	 * more clever if the first half of the instruction is
	 * accessible but the second half isn't, but I don't really
	 * care that much.  The worst case is that we set some watch
	 * points in some stupid places soem small fraction of a
	 * second before the program crashes. */
	(void)_fetch_bytes(p, urs->rip, instr, sizeof(instr));

	/* Find out what memory location it's accessing. */
	find_instr_template(instr, urs->rip, &it, &prefixes);
	assert(it.modrm_access_type != ACCESS_INVALID &&
	       it.modrm_access_type != ACCESS_NONE);
	modrm_addr = eval_modrm_addr(instr + it.bytes_prefix + it.bytes_opcode,
				     &it,
				     prefixes,
				     urs);

	if (it.modrm_access_type == ACCESS_R)
		wp = set_watchpoint(p->process, modrm_addr, 8, 0);
	else
		wp = set_watchpoint(p->process, modrm_addr, 8, 1);

	timer_fired = false;

	memset(&itimer, 0, sizeof(itimer));
	itimer.it_value.tv_sec = DELAY_WHEN_BREAKPOINT_HIT;
	itimer.it_value.tv_usec = (DELAY_WHEN_BREAKPOINT_HIT - itimer.it_value.tv_sec) * 1e6;
	setitimer(ITIMER_REAL, &itimer, NULL);

	do {
		struct thread *other;
		bool nothing_running = true;

		/* XXX there's a massive race here: if the alarm fires
		   between the test of timer_fired and the wait
		   syscall we'll deadlock! */
		receive_ptrace_event(p->process);
		for (other = p->process->head_thread;
		     other;
		     other = other->next) {
			if (other == p)
				continue;
			if (!thr_is_stopped(other)) {
				nothing_running = false;
				continue;
			}
			if (WIFSTOPPED(thr_stop_status(other)) &&
			    WSTOPSIG(thr_stop_status(other)) == SIGTRAP) {
				/* It stopped for either a watchpoint
				 * or a breakpoint.  Find out
				 * which. */
				siginfo_t si;
				if (ptrace(PTRACE_GETSIGINFO, other->pid, NULL, &si) < 0)
					err(1, "PTRACE_GETSIGINFO");
				if (si.si_code == TRAP_HWBKPT) {
					/* It's one of our watch
					 * points.  Report the
					 * race. */
					report_race(p, other);
					/* Kick it off again */
					resume_child(other);

					nothing_running = false;
				} else {
					/* It was a breakpoint.  Leave
					   it; we'll pick it up
					   later. */
				}
			}
		}
		if (nothing_running) {
			/* The itimer will interrupt any syscalls.
			   Make sure we cancel it before going any
			   further, to avoid confusion. */
			printf("Every thread stopped.\n");
			memset(&itimer, 0, sizeof(itimer));
			setitimer(ITIMER_REAL, &itimer, NULL);
			break;
		}
	} while (!timer_fired);

	unset_watchpoint(wp);

	install_breakpoints(p, bp->lo);

	sanity_check_lo(bp->lo);
}

static bool
shlib_interesting(char *fname)
{
	char *f = basename(fname);
	return strcmp(f, target_binary) == 0;
}

static void
unloaded_object(struct thread *thr, struct loaded_object *lo)
{
	printf("Unloaded %s\n", lo->name);

	while (lo->head_bp)
		unset_breakpoint(thr, lo->head_bp);

	if (lo->next)
		lo->next->prev = lo->prev;
	if (lo->prev) {
		lo->prev->next = lo->next;
	} else {
		assert(thr->process->head_loaded_object == lo);
		thr->process->head_loaded_object = lo->next;
	}
	free(lo->name);
	free(lo->instrs);
	free(lo);
}

static void
linker_did_something(struct thread *thr, struct breakpoint *_ign1, void *_ign2,
		     struct user_regs_struct *_ign3)
{
	FILE *f;
	char *path;
	struct loaded_object *lo;
	struct process *p = thr->process;

	for (lo = p->head_loaded_object; lo; lo = lo->next)
		lo->live = false;

	asprintf(&path, "/proc/%d/maps", thr->pid);
	f = fopen(path, "r");
	if (!f)
		err(1, "fopen(%s, \"r\")", path);
	free(path);

	while (!feof(f)) {
		unsigned long start, end;
		char readable, writable, executable, shared;
		unsigned long offset;
		unsigned major, minor, inode;
		char *fname;
		int r;
		char *fname2;
		struct loaded_object *lo;

		r = fscanf(f,
			   "%lx-%lx %c%c%c%c %lx %x:%x %d%a[^\n]\n",
			   &start,
			   &end,
			   &readable,
			   &writable,
			   &executable,
			   &shared,
			   &offset,
			   &major,
			   &minor,
			   &inode,
			   &fname);
		if (r == -1)
			err(1, "reading /proc/pid/maps (%d)", r);
		if (r != 11) {
			if (ferror(f))
				err(1, "reading /proc/pid/maps");
			if (feof(f))
				break;
			errx(1, "unknown error reading /proc/pid/maps (%d)", r);
		}

		for (fname2 = fname;
		     fname2[0] && isspace(fname2[0]);
		     fname2++)
			;

		if (shared == 'p' &&
		    executable == 'x' &&
		    shlib_interesting(fname2)) {
			lo = process_shlib(p, start, end, offset, fname2);
			if (lo)
				install_breakpoints(p->head_thread, lo);
		}

		free(fname);
	}

	while (p->head_loaded_object &&
	       !p->head_loaded_object->live) {
		struct loaded_object *next = p->head_loaded_object->next;
		unloaded_object(thr, p->head_loaded_object);
		p->head_loaded_object = next;
	}
	if (p->head_loaded_object) {
		struct loaded_object *next;
		for (lo = p->head_loaded_object;
		     lo->next;
		     lo = next) {
			if (!lo->next->live) {
				next = lo->next->next;
				unloaded_object(thr, lo->next);
				lo->next = next;
				next = lo;
			} else {
				next = lo->next;
			}
		}
	}

	fclose(f);
}

static int
get_stop_status(pid_t pid, struct pending_wait_status *pws)
{
	int x;
	int status;

	for (x = 0; x < pws->nr_pending; x++) {
		if (pws->pending[x].pid == pid) {
			/* The STOP has already been reported by the
			   kernel.  Use the stashed value. */
			status = pws->pending[x].status;
			memmove(pws->pending + x,
				pws->pending + x + 1,
				sizeof(pws->pending[0]) & (pws->nr_pending - x - 1));
			pws->nr_pending--;
			return status;
		}
	}
	if (waitpid(pid, &status, __WALL) < 0)
		err(1, "waitpid() for new thread %d", pid);
	return status;
}

static void
handle_clone(struct thread *parent)
{
	struct thread *thr;
	unsigned long new_pid;
	int status;

	if (ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &new_pid) < 0)
		err(1, "PTRACE_GETEVENTMSG() for clone");
	printf("New pid %ld\n", new_pid);
	thr = calloc(sizeof(*thr), 1);
	thr->pid = new_pid;
	thr->process = parent->process;
	status = get_stop_status(new_pid, &parent->process->pws);
	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "unexpected waitpid status %d for clone\n", status);
		abort();
	}

	/* Set up the normal options */
	if (ptrace(PTRACE_SETOPTIONS, thr->pid, NULL, PTRACE_OPTIONS) < 0)
		err(1, "ptrace(PTRACE_SETOPTIONS) for new thread");

	/* Enlist the new thread in the process */
	thr->next = parent->process->head_thread;
	if (parent->process->head_thread)
		parent->process->head_thread->prev = thr;
	parent->process->head_thread = thr;
	parent->process->nr_threads++;

	/* And let them both go */
	resume_child(thr);
	resume_child(parent);
}

/* The child fork()ed.  We're not going to trace the new process, but
   we do need to make sure we get rid of all of our breakpoints. */
static void
handle_fork(struct thread *thr)
{
	unsigned long new_pid;
	int status;
	struct breakpoint *bp;
	struct thread new_thr;

	/* Wait for the kernel to attach it to us */
	if (ptrace(PTRACE_GETEVENTMSG, thr->pid, NULL, &new_pid) < 0)
		err(1, "PTRACE_GETEVENTMSG() for fork");
	status = get_stop_status(new_pid, &thr->process->pws);
	if (!WIFSTOPPED(status))
		errx(1, "unexpected status %x for fork", status);

	/* Hack: fake up a thread structure so that we have something
	 * to pass to store_byte */
	bzero(&new_thr, sizeof(new_thr));
	new_thr.pid = new_pid;
	for (bp = thr->process->head_breakpoint; bp; bp = bp->next)
		store_byte(&new_thr, bp->addr, bp->old_content);

	/* Detach it and let it go */
	if (ptrace(PTRACE_DETACH, new_pid) < 0)
		err(1, "detaching forked child");

	printf("%d forked %zd, ignoring...\n", thr->pid, new_pid);
}

static void
thread_exited(struct thread *thr, int status)
{
	printf("Thread %d exited\n", thr->pid);
	if (thr->next)
		thr->next->prev = thr->prev;
	if (thr->prev)
		thr->prev->next = thr->next;
	else
		thr->process->head_thread = thr->next;
	thr->process->nr_threads--;
	if (thr->process->nr_threads == 0)
		exit(status);
	free(thr);
}

int
main(int argc, char *argv[], char *environ[])
{
	struct process *child;
	int r;
	struct sigaction timer_sa;

	bzero(&timer_sa, sizeof(timer_sa));

	timer_sa.sa_handler = itimer_handler;
	sigemptyset(&timer_sa.sa_mask);
	if (sigaction(SIGALRM, &timer_sa, NULL) < 0)
		err(1, "installing SIGALRM handler");

	target_binary = basename(argv[1]);

	child = spawn_child(argv[1], argv + 1);

	/* Child starts stopped. */
	assert(child->nr_threads == 1);
	resume_child(child->head_thread);

	/* Get the break address */
	r = read(child->from_child_fd, &child->linker_brk_addr,
		 sizeof(child->linker_brk_addr));
	if (r != sizeof(child->linker_brk_addr))
		err(1, "reading child's linker break address");
	pause_child(child->head_thread);
	set_breakpoint(child->head_thread, child->linker_brk_addr, NULL,
		       linker_did_something, NULL);
	linker_did_something(child->head_thread, NULL, NULL, NULL);
	resume_child(child->head_thread);

	/* Close out our file descriptors to set it going properly. */
	close(child->from_child_fd);
	close(child->to_child_fd);

	/* wait() and friends don't have convenient timeout arguments,
	   and doing it with signals is a pain, so just have a child
	   process which sleeps 60 seconds and then exits. */
	child->timeout_pid = fork();
	if (child->timeout_pid == 0) {
		sleep(RESET_BREAKPOINTS_TIMEOUT);
		_exit(0);
	}

	while (1) {
		struct thread *thr;

		if (child->timeout_fired) {
			int status;
			struct loaded_object *lo;

			child->timeout_fired = false;
			child->timeout_pid = fork();
			if (child->timeout_pid == 0) {
				sleep(RESET_BREAKPOINTS_TIMEOUT);
				_exit(0);
			}

			status = child->head_thread->_stop_status;
			if (status == -1)
				pause_child(child->head_thread);

			for (lo = child->head_loaded_object; lo; lo = lo->next) {
				clear_all_breakpoints(child->head_thread, lo);
				install_breakpoints(child->head_thread, lo);
			}

			if (status == -1)
				unpause_child(child->head_thread);
		}

		for (thr = child->head_thread; thr && !thr_is_stopped(thr); thr = thr->next)
			;
		if (!thr) {
			receive_ptrace_event(child);
			continue;
		}

		if (WIFEXITED(thr_stop_status(thr))) {
			printf("Child exited with status %d, doing the same thing (%x)\n",
			       WEXITSTATUS(thr_stop_status(thr)), thr_stop_status(thr));
			thread_exited(thr, WEXITSTATUS(thr_stop_status(thr)));
		} else if (WIFSIGNALED(thr_stop_status(thr))) {
			printf("Child got signal %d\n", WTERMSIG(thr_stop_status(thr)));
			/* Should arguably raise() the signal here,
			   rather than exiting, so that our parent
			   gets the right status, but that might cause
			   us to dump core, which would potentially
			   obliterate any core dump left behind by the
			   child. */
			exit(1);
		} else if (WIFSTOPPED(thr_stop_status(thr)) &&
			   WSTOPSIG(thr_stop_status(thr)) == SIGTRAP) {
			switch (thr_stop_status(thr) >> 16) {
			case 0:
				handle_breakpoint(thr);
				break;
			case PTRACE_EVENT_FORK:
				handle_fork(thr);
				break;
			case PTRACE_EVENT_CLONE:
				handle_clone(thr);
				break;
			default:
				fprintf(stderr, "unknown ptrace event %d\n", thr_stop_status(thr) >> 16);
				abort();
			}
		} else if (WIFSTOPPED(thr_stop_status(thr)) &&
			   WSTOPSIG(thr_stop_status(thr)) == SIGSTOP) {
			/* Sometimes get these spuriously when
			 * attaching to a new thread or as a resule of
			 * pause_thread().  Ignore. */
			resume_child(thr);
		} else if (WIFSTOPPED(thr_stop_status(thr))) {
			printf("Sending signal %d to child %d\n",
			       WSTOPSIG(thr_stop_status(thr)), thr->pid);
			if (ptrace(PTRACE_CONT, thr->pid, NULL,
				   (unsigned long)WSTOPSIG(thr_stop_status(thr))) < 0)
				err(1, "forwarding signal %d to child %d with ptrace",
				    WSTOPSIG(thr_stop_status(thr)), thr->pid);
			thr_resume(thr);
		} else {
			fprintf(stderr, "unexpected waitpid status %x\n", thr_stop_status(thr));
			abort();
		}
	}
	return 0;
}

