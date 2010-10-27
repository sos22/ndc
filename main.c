#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <argp.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ndc.h"

static unsigned target_breakpoint_ratio = 10; /* One in n accesses
						  gets a
						  breakpoint. */
static double reset_breakpoints_timeout = 1; /* in seconds */
static double delay_when_breakpoint_hit = 0.001; /* in seconds */
static bool exit_on_first_race;
static bool writes_sufficient = true; /* Only set breakpoints on
					 writes.  We always set
					 watchpoints for reads */
static const char *target_binary;

static bool do_stats;
static unsigned long nr_evals;
static unsigned long nr_stack_evals;

static pid_t pid_to_attach_to;

#define PRELOAD_LIB_NAME "/local/scratch/sos22/notdc/ndc.so"
#define PTRACE_OPTIONS (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC)

static void memory_access_breakpoint(struct thread *p, struct breakpoint *bp, void *ctxt,
				     struct user_regs_struct *urs);

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

/* Invoked as an on_exit handler to do any necessary final cleanup */
static void
kill_child(int ign, void *_child)
{
	struct process *child = _child;
	struct thread *thr;
	while (!list_empty(&child->threads)) {
		thr = list_pop(struct thread, list, &child->threads);
		tgkill(child->tgid, thr->pid, SIGKILL);
	}
}

static struct process *
spawn_child(const char *path, char *const argv[])
{
	struct process *work;
	struct thread *thr;
	int p1[2], p2[2];

	work = calloc(sizeof(*work), 1);
	init_list_head(&work->threads);
	init_list_head(&work->breakpoints);
	init_list_head(&work->loaded_objects);

	thr = calloc(sizeof(*thr), 1);
	thr->process = work;
	thr->_stop_status = -1;

	list_push(thr, list, &work->threads);
	work->nr_threads = 1;
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
add_mem_access_instr(struct loaded_object *lo, unsigned long addr, int mode)
{
	if (writes_sufficient && mode == ACCESS_R)
		return;

	msg(1, "Found memory accessing instruction at %#lx\n", addr);

	if (lo->nr_instrs == lo->nr_instrs_alloced) {
		lo->nr_instrs_alloced *= 3;
		lo->instrs = realloc(lo->instrs, sizeof(lo->instrs[0]) * lo->nr_instrs_alloced);
	}
	lo->instrs[lo->nr_instrs] = addr;
	lo->nr_instrs++;
}

/* Store all of the reported races in a hash table, so that we can
 * filter out duplicates. */
struct reported_race {
	struct reported_race *next;
	unsigned long rip1;
	unsigned long rip2;
};
/* This really doesn't want to be a power of two, or the hash gets
   *much* weaker */
#define RR_HASH_SIZE 129
static struct reported_race *
rr_hash[RR_HASH_SIZE];

static void
report_race(struct thread *thr1, struct thread *thr2)
{
	struct user_regs_struct urs1, urs2;
	unsigned hash;
	struct reported_race *rr;
	static int nr_surpressed;

	get_regs(thr1, &urs1);
	get_regs(thr2, &urs2);
	hash = (urs1.rip ^ urs2.rip) % RR_HASH_SIZE;
	for (rr = rr_hash[hash]; rr; rr = rr->next) {
		if (rr->rip1 == urs1.rip &&
		    rr->rip2 == urs2.rip)
			break;
	}
	if (rr) {
		nr_surpressed++;
		printf("Suppressed %d duplicates...\r",
		       nr_surpressed);
		fflush(stdout);
	} else {
		msg(100,
		    "Race detected between pid %d RIP %lx and pid %d RIP %lx      \n",
		    thr1->pid,
		    urs1.rip,
		    thr2->pid,
		    urs2.rip);
		nr_surpressed = 0;
		rr = calloc(sizeof(*rr), 1);
		rr->rip1 = urs1.rip;
		rr->rip2 = urs2.rip;
		rr->next = rr_hash[hash];
		rr_hash[hash] = rr;
	}

	if (exit_on_first_race)
		exit(0);
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
	struct breakpoint *bp;

	while (!list_empty(&lo->breakpoints)) {
		bp = list_pop(struct breakpoint, list_loaded_object, &lo->breakpoints);
		unset_breakpoint(thr, bp);
	}
}

static void
install_breakpoints(struct thread *thr, struct loaded_object *lo)
{
	unsigned target_nr_breakpoints;
	struct breakpoint *bp;
	unsigned x;
	unsigned long addr;
	bool found_it;

	target_nr_breakpoints = lo->nr_instrs / target_breakpoint_ratio;

	sanity_check_lo(lo);
	while (lo->nr_breakpoints < target_nr_breakpoints) {
		x = lo->next_instr_to_set_bp_on++ % lo->nr_instrs;
		addr = lo->instrs[x];
		found_it = false;
		list_foreach(&lo->breakpoints, bp, list_loaded_object) {
			if (bp->addr == addr) {
				found_it = true;
				break;
			}
		}
		if (found_it)
			continue;
		bp = set_breakpoint(thr, lo->instrs[x], lo, memory_access_breakpoint, lo);
		list_push(bp, list_loaded_object, &lo->breakpoints);
		lo->nr_breakpoints++;
	}
	sanity_check_lo(lo);
}

static void
memory_access_breakpoint(struct thread *p, struct breakpoint *bp, void *ctxt,
			 struct user_regs_struct *urs)
{
	unsigned char instr[16];
	struct instr_template it;
	unsigned long modrm_addr;
	struct watchpoint *wp;
	struct itimerval itimer;
	struct loaded_object *lo = bp->lo;

	assert(bp->lo);
	sanity_check_lo(bp->lo);

	/* No longer need this breakpoint. */
	unset_breakpoint(p, bp);
	bp = NULL;
	set_regs(p, urs);

	if (p->process->nr_threads == 1) {
		printf("Still single-threaded?\n");
		install_breakpoints(p, lo);
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
	find_instr_template(instr, urs->rip, &it);
	assert(it.modrm_access_type != ACCESS_INVALID &&
	       it.modrm_access_type != ACCESS_NONE);
	modrm_addr = eval_modrm_addr(instr + it.bytes_prefix + it.bytes_opcode,
				     &it,
				     urs);

	nr_evals++;
	if (modrm_addr >= urs->rsp - 128 && modrm_addr < urs->rsp + 4096)
		nr_stack_evals++;

	if (it.modrm_access_type == ACCESS_R)
		wp = set_watchpoint(p->process, modrm_addr, 8, 0);
	else
		wp = set_watchpoint(p->process, modrm_addr, 8, 1);

	timer_fired = false;

	memset(&itimer, 0, sizeof(itimer));
	itimer.it_value.tv_sec = delay_when_breakpoint_hit;
	itimer.it_value.tv_usec = (delay_when_breakpoint_hit - itimer.it_value.tv_sec) * 1e6;
	setitimer(ITIMER_REAL, &itimer, NULL);

	do {
		struct thread *other;
		bool nothing_running = true;

		/* XXX there's a massive race here: if the alarm fires
		   between the test of timer_fired and the wait
		   syscall we'll deadlock! */
		receive_ptrace_event(p->process);
		list_foreach(&p->process->threads, other, list) {
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
			msg(9, "Every thread stopped.\n");
			memset(&itimer, 0, sizeof(itimer));
			setitimer(ITIMER_REAL, &itimer, NULL);
			break;
		}
	} while (!timer_fired);

	unset_watchpoint(wp);

	install_breakpoints(p, lo);

	sanity_check_lo(lo);
}

static bool
shlib_interesting(char *fname)
{
	char *f = basename(fname);
	printf("Is %s interesting? (want %s\n", f, target_binary);
	return strcmp(f, target_binary) == 0;
}

static void
unloaded_object(struct thread *thr, struct loaded_object *lo)
{
	msg(50, "Unloaded %s\n", lo->name);

	clear_all_breakpoints(thr, lo);
	while (!list_empty(&lo->functions)) {
		struct function *f = list_pop(struct function, list, &lo->functions);
		free(f->name);
		free(f);

	}

	list_unlink(&lo->list);
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
	struct loaded_object *next_lo;
	struct process *p = thr->process;

	list_foreach(&p->loaded_objects, lo, list)
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
			if (lo) {
				if (lo->nr_instrs < target_breakpoint_ratio)
					printf("%s has %d breakpointable instructions, and we want to monitor one in %d, which means that we'll monitor 0\n",
					       fname,
					       lo->nr_instrs,
					       target_breakpoint_ratio);
				install_breakpoints(list_first(&p->threads, struct thread, list), lo);
			}
		}

		free(fname);
	}

	list_foreach_careful(&p->loaded_objects,
			     lo,
			     list,
			     next_lo) {
		if (!lo->live)
			unloaded_object(thr, lo);
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
	msg(50, "New pid %ld\n", new_pid);
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
	list_push(thr, list, &parent->process->threads);
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
	list_foreach(&thr->process->breakpoints, bp, list_process)
		store_byte(&new_thr, bp->addr, bp->old_content);

	/* Detach it and let it go */
	if (ptrace(PTRACE_DETACH, new_pid) < 0)
		err(1, "detaching forked child");

	msg(10, "%d forked %zd, ignoring...\n", thr->pid, new_pid);
}

static void
thread_exited(struct thread *thr, int status)
{
	msg(50, "Thread %d exited\n", thr->pid);
	list_unlink(&thr->list);
	thr->process->nr_threads--;
	if (thr->process->nr_threads == 0) {
		assert(list_empty(&thr->process->threads));
		exit(status);
	}
	free(thr);
}

static void
maybe_dump_debug_ring(int code, void *ignore)
{
	if (code != 0)
		dump_debug_ring();
}

static int
parse_int_argument(const char *x)
{
	char *e;
	long r;

	errno = 0;
	r = strtol(x, &e, 10);
	if (!e || *e)
		errno = EINVAL;
	if (errno)
		err(1, "expected an integer, got %s", x);
	if (r != (int)r)
		errx(1, "%ld is out of range", r);
	return r;
}

static double
parse_double_argument(const char *x)
{
	char *e;
	double r;

	errno = 0;
	r = strtod(x, &e);
	if (!e || *e)
		errno = EINVAL;
	if (errno)
		err(1, "expected a double, got %s", x);
	return r;
}

static struct argp_option argp_options[] = {
	{ .name = "bp-ratio",
	  .key = 'r',
	  .arg = "INTEGER" },
	{ .name = "reset-timeout",
	  .key = 't',
	  .arg = "SECONDS" },
	{ .name = "bp-delay",
	  .key = 'd',
	  .arg = "SECONDS" },
	{ .name = "exit-on-race",
	  .key = 'x' },
	{ .name = "break-on-read",
	  .key = 'b' },
	{ .name = "stats",
	  .key = 's' },
	{ .name = "pid",
	  .key = 'p',
	  .arg = "PID"},
	{ 0 }
};

static error_t
argp_parser(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'r':
		target_breakpoint_ratio = parse_int_argument(arg);
		return 0;
	case 't':
		reset_breakpoints_timeout = parse_double_argument(arg);
		return 0;
	case 'd':
		delay_when_breakpoint_hit = parse_double_argument(arg);
		return 0;
	case 'x':
		exit_on_first_race = true;
		return 0;
	case 'b':
		writes_sufficient = false;
		return 0;
	case 's':
		do_stats = true;
		return 0;
	case 'p':
		pid_to_attach_to = parse_int_argument(arg);
		return 0;
	default:
		return ARGP_ERR_UNKNOWN;
	}
}

static struct argp argp = {
	.options = argp_options,
	.parser = argp_parser
};

static struct process *
start_process(char *argv[])
{
	int r;
	struct process *child;
	struct thread *head_thr;

	child = spawn_child(argv[0], argv);
	assert(child->nr_threads == 1);
	head_thr = list_first(&child->threads, struct thread, list);

	/* Child starts stopped. */
	resume_child(head_thr);

	/* Get the break address */
	r = read(child->from_child_fd, &child->linker_brk_addr,
		 sizeof(child->linker_brk_addr));
	if (r != sizeof(child->linker_brk_addr))
		err(1, "reading child's linker break address");
	pause_child(head_thr);
	set_breakpoint(head_thr, child->linker_brk_addr, NULL,
		       linker_did_something, NULL);
	linker_did_something(head_thr, NULL, NULL, NULL);
	resume_child(head_thr);

	/* Close out our file descriptors to set it going properly. */
	close(child->from_child_fd);
	close(child->to_child_fd);

	return child;
}

static void
attach_thread(struct process *proc, pid_t tid)
{
	struct thread *thr;
	thr = calloc(sizeof(*thr), 1);
	thr->process = proc;
	thr->pid = tid;
	thr->_stop_status = -1;
	list_push(thr, list, &proc->threads);
	proc->nr_threads++;

	if (ptrace(PTRACE_ATTACH, tid) < 0)
		err(1, "PTRACE_ATTACH(%d)", tid);
	while (!thr_is_stopped(thr))
		receive_ptrace_event(proc);

	if (!WIFSTOPPED(thr_stop_status(thr)) ||
	    WSTOPSIG(thr_stop_status(thr)) != SIGSTOP)
		errx(1, "strange status %x from waitpid()",
		     thr_stop_status(thr));

	if (ptrace(PTRACE_SETOPTIONS,
		   thr->pid,
		   NULL,
		   PTRACE_OPTIONS) < 0)
		err(1, "ptrace(PTRACE_SETOPTIONS)");
}

static struct process *
attach_process(pid_t pid)
{
	struct process *proc;
	bool progress;

	proc = calloc(sizeof(*proc), 1);
	init_list_head(&proc->threads);
	proc->from_child_fd = -1;
	proc->to_child_fd = -1;
	proc->tgid = pid;
	init_list_head(&proc->breakpoints);
	init_list_head(&proc->loaded_objects);

	/* Okay.  Now we try to capture all of the threads which it's
	 * already spawned.  This is kind of tricky, because it might
	 * spawn some more while we're working, so need to iterate to
	 * fixed point. */
	/* (It's also possible that some threads might exit while
	 * we're doing this, but that's okay because we'll pick up the
	 * exit message as soon as we return and fix up from
	 * there.) */

	do {
		DIR *d;
		char *p;
		progress = false;
		asprintf(&p, "/proc/%d/task", pid);
		d = opendir(p);
		if (!d)
			err(1, "opening %s", p);
		free(p);
		while (1) {
			struct dirent *de;
			pid_t new_pid;
			struct thread *thr;

		next_de:
			de = readdir(d);
			if (!de)
				break;
			if (!strcmp(de->d_name, ".") ||
			    !strcmp(de->d_name, ".."))
				continue;
			new_pid = parse_int_argument(de->d_name);
			/* Do we already know about this thread? */
			list_foreach(&proc->threads, thr, list) {
				if (thr->pid == new_pid)
					goto next_de;
			}
			/* Thread isn't known.  Attach it. */
			attach_thread(proc, new_pid);

			/* There were unattached threads at the start
			   of this iteration, so we need to go around
			   again. */
			progress = true;
		}
		closedir(d);
	} while (progress);

	linker_did_something(list_first(&proc->threads, struct thread, list), NULL, NULL, NULL);

	/* Should now be fully attached. */
	return proc;
}


int
main(int argc, char *argv[])
{
	struct process *child;
	struct thread *head_thr;
	struct sigaction timer_sa;
	int arg_index;

	on_exit(maybe_dump_debug_ring, NULL);
	signal(SIGABRT, (void (*)(int))dump_debug_ring);
	bzero(&timer_sa, sizeof(timer_sa));
	timer_sa.sa_handler = itimer_handler;
	sigemptyset(&timer_sa.sa_mask);
	if (sigaction(SIGALRM, &timer_sa, NULL) < 0)
		err(1, "installing SIGALRM handler");

	errno = argp_parse(&argp, argc, argv, 0, &arg_index, NULL);
	if (errno)
		err(1, "parsing arguments");

	target_binary = basename(argv[arg_index]);

	if (pid_to_attach_to == 0)
		child = start_process(argv + arg_index);
	else
		child = attach_process(pid_to_attach_to);

	/* wait() and friends don't have convenient timeout arguments,
	   and doing it with signals is a pain, so just have a child
	   process which sleeps 60 seconds and then exits. */
	child->timeout_pid = fork();
	if (child->timeout_pid == 0) {
		dsleep(reset_breakpoints_timeout);
		_exit(0);
	}

	while (1) {
		struct thread *thr;
		bool nothing_ready;

		if (child->timeout_fired) {
			int status;
			struct loaded_object *lo;

			child->timeout_fired = false;
			child->timeout_pid = fork();
			if (child->timeout_pid == 0) {
				dsleep(reset_breakpoints_timeout);
				_exit(0);
			}

			head_thr = list_first(&child->threads, struct thread, list);
			status = head_thr->_stop_status;
			if (status == -1)
				pause_child(head_thr);

			list_foreach(&child->loaded_objects, lo, list) {
				clear_all_breakpoints(head_thr, lo);
				install_breakpoints(head_thr, lo);
			}

			if (status == -1)
				unpause_child(head_thr);

			if (do_stats)
				printf("Stack ratio %f\n", (double)nr_stack_evals/nr_evals);
		}

		nothing_ready = true;
		list_foreach(&child->threads, thr, list) {
			if (thr_is_stopped(thr)) {
				nothing_ready = false;
				break;
			}
		}
		if (nothing_ready) {
			receive_ptrace_event(child);
			continue;
		}

		assert(thr_is_stopped(thr));

		if (WIFEXITED(thr_stop_status(thr))) {
			msg(15, "Child exited with status %d, doing the same thing (%x)\n",
			       WEXITSTATUS(thr_stop_status(thr)), thr_stop_status(thr));
			thread_exited(thr, WEXITSTATUS(thr_stop_status(thr)));
		} else if (WIFSIGNALED(thr_stop_status(thr))) {
			msg(100, "Child got signal %d\n", WTERMSIG(thr_stop_status(thr)));
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
			msg(20, "Sending signal %d to child %d\n",
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

