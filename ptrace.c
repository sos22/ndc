/* Various wrappers around low-level ptrace things */
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

#define offsetof(field, strct) ((unsigned long)&((strct *)0)->field)

static unsigned long
fetch_ulong(struct thread *thr, unsigned long addr)
{
	unsigned long buf;
	assert(thr_is_stopped(thr));
	errno = 0;
	buf = ptrace(PTRACE_PEEKDATA, thr->pid, addr);
	if (errno != 0)
		err(1, "peek(%lx)", addr);
	return buf;
}

static unsigned char
fetch_byte(struct thread *thr, unsigned long addr)
{
	unsigned byte_idx;
	union {
		unsigned long buf;
		unsigned char bytes[8];
	} u;
	byte_idx = addr % 8;
	addr -= byte_idx;
	u.buf = fetch_ulong(thr, addr);
	return u.bytes[byte_idx];
}

/* Underscore because you need to think about the return value */
int
_fetch_bytes(struct thread *thr, unsigned long addr, void *buf, size_t buf_size)
{
	/* We fetch a super-range of the desired [addr,
	   addr+buf_size), so as to get proper alignment, and then
	   memcpy to the output buffer. */
	unsigned long *aligned_buf;
	unsigned long real_start = addr;
	unsigned long real_end = addr+buf_size;
	unsigned long align_start = addr & ~7ul;
	unsigned long align_end = (real_end + 7) & ~7ul;
	unsigned long cursor;

	assert(thr_is_stopped(thr));
	aligned_buf = alloca(align_end - align_start);
	errno = 0;
	for (cursor = align_start; cursor != align_end; cursor += 8) {
		aligned_buf[(cursor - align_start)/8] =
			ptrace(PTRACE_PEEKDATA, thr->pid, cursor);
		if (errno != 0) {
			/* Failed */
			free(aligned_buf);
			return -1;
		}
	}
	memcpy(buf, (void *)aligned_buf + real_start - align_start, buf_size);
	return 0;
}

static void
store_ulong(struct thread *thr, unsigned long addr, unsigned long ulong)
{
	assert(thr_is_stopped(thr));
	msg(0, "%d: %lx@%lx -> %lx\n", thr->pid, fetch_ulong(thr, addr), addr, ulong);
	if (ptrace(PTRACE_POKEDATA, thr->pid, addr, ulong) < 0)
		err(1, "poke(%lx, %lx)", addr, ulong);
}

void
store_byte(struct thread *thr, unsigned long addr, unsigned char byte)
{
	unsigned byte_idx;
	union {
		unsigned long buf;
		unsigned char bytes[8];
	} u;
	byte_idx = addr % 8;
	addr -= byte_idx;
	u.buf = fetch_ulong(thr, addr);
	u.bytes[byte_idx] = byte;
	store_ulong(thr, addr, u.buf);
}

struct breakpoint *
set_breakpoint(struct thread *thr,
	       unsigned long addr,
	       struct loaded_object *lo,
	       void (*f)(struct thread *, struct breakpoint *, void *ctxt,
			 struct user_regs_struct *urs),
	       void *ctxt)
{
	struct breakpoint *bp = calloc(sizeof(*bp), 1);

	bp->addr = addr;
	bp->f = f;
	bp->ctxt = ctxt;
	bp->lo = lo;
	bp->next = thr->process->head_breakpoint;
	if (thr->process->head_breakpoint)
		thr->process->head_breakpoint->prev = bp;
	thr->process->head_breakpoint = bp;

	bp->old_content = fetch_byte(thr, addr);
	store_byte(thr, addr, 0xcc);

	return bp;
}

void
unset_breakpoint(struct thread *thr, struct breakpoint *bp)
{
	store_byte(thr, bp->addr, bp->old_content);
	if (bp->next)
		bp->next->prev = bp->prev;
	if (bp->prev)
		bp->prev->next = bp->next;
	else
		thr->process->head_breakpoint = bp->next;

	if (bp->lo) {
		if (bp == bp->lo->head_bp) {
			assert(!bp->prev_lo);
			bp->lo->head_bp = bp->next_lo;
		} else if (bp->prev_lo) {
			bp->prev_lo->next_lo = bp->next_lo;
		}
		if (bp->next_lo)
			bp->next_lo->prev_lo = bp->prev_lo;
		assert(bp->lo->nr_breakpoints);
		bp->lo->nr_breakpoints--;
	}

	free(bp);
}

static struct thread *
find_thread_by_pid(struct process *p, pid_t pid)
{
	struct thread *thr;
	for (thr = p->head_thread; thr && thr->pid != pid; thr = thr->next)
		;
	return thr;
}

static bool
check_pending_waits(struct process *proc)
{
	unsigned x;
	struct thread *thr;
	bool done_something;

	done_something = false;

	for (x = 0; x < proc->pws.nr_pending; ) {
		thr = find_thread_by_pid(proc, proc->pws.pending[x].pid);
		if (thr) {
			thr_stopped(thr, proc->pws.pending[x].status);
			memmove(proc->pws.pending + x,
				proc->pws.pending + x + 1,
				sizeof(proc->pws.pending[0]) * (proc->pws.nr_pending - x - 1));
			proc->pws.nr_pending--;
			done_something = true;
		} else {
			x++;
		}
	}
	return done_something;
}

static void
push_pending_wait_status(struct pending_wait_status *pws, pid_t pid, int status)
{
	if (pws->nr_pending == pws->nr_allocated) {
		pws->nr_allocated += 8;
		pws->pending = realloc(pws->pending,
				       sizeof(pws->pending[0]) * pws->nr_allocated);
	}
	pws->pending[pws->nr_pending].status = status;
	pws->pending[pws->nr_pending].pid = pid;
	pws->nr_pending++;
}

bool
receive_ptrace_event(struct process *proc)
{
	pid_t pid;
	int status;
	struct thread *thr;

	if (check_pending_waits(proc))
		return true;

	pid = waitpid(-1, &status, __WALL);
	if (pid < 0) {
		if (errno == EINTR)
			return false;
		err(1, "waitpid()");
	}

	if (pid == proc->timeout_pid) {
		proc->timeout_fired = true;
		return false;
	}

	assert(status != -1);

	thr = find_thread_by_pid(proc, pid);
	if (thr)
		thr_stopped(thr, status);
	else
		push_pending_wait_status(&proc->pws, pid, status);

	return true;
}

bool
pause_child(struct thread *thr)
{
	if (thr_is_stopped(thr))
		return true;
	if (tgkill(thr->process->tgid, thr->pid, SIGSTOP) < 0)
		err(1, "kill(SIGSTOP)");
	while (!thr_is_stopped(thr))
		if (!receive_ptrace_event(thr->process))
			return false;
	return true;
}

void
resume_child(struct thread *thr)
{
	if (!thr_is_stopped(thr))
		return;
	if (ptrace(PTRACE_CONT, thr->pid, NULL, NULL) < 0)
		err(1, "ptrace(PTRACE_CONT) from resume_child()");
	thr_resume(thr);
}

void
unpause_child(struct thread *thr)
{
	if (WIFSTOPPED(thr_stop_status(thr)) &&
	    WSTOPSIG(thr_stop_status(thr)) == SIGSTOP)
		resume_child(thr);
}

/* Only need one at a time, so this is trivial. */
struct watchpoint {
};

struct watchpoint *
set_watchpoint(struct process *p, unsigned long addr, unsigned size, int watch_reads)
{
	struct thread *thr;
	bool running;

	/* Encode using the weird-arse scheme the debug registers
	 * use */
	switch (size) {
	case 1:
		size = 0;
		break;
	case 2:
		size = 1;
		break;
	case 4:
		size = 3;
		break;
	case 8:
		size = 2;
		break;
	default:
		abort();
	}

	for (thr = p->head_thread; thr; thr = thr->next) {
		running = !thr_is_stopped(thr);
		if (running)
			while (!pause_child(thr))
				;
		assert(thr_is_stopped(thr));

		if (ptrace(PTRACE_POKEUSER, thr->pid,
			   offsetof(u_debugreg[0], struct user),
			   addr) < 0)
			err(1, "Setting debug register 0 of %d", thr->pid);
		if (ptrace(PTRACE_POKEUSER, thr->pid,
			   offsetof(u_debugreg[7], struct user),
			   (size << 18) |
			   ((watch_reads ? 3 : 1) << 16) |
			   1) < 0)
			err(1, "Setting debug register 7 of %d", thr->pid);

		if (running)
			unpause_child(thr);
	}

	return (struct watchpoint *)p;
}

void
unset_watchpoint(struct watchpoint *w)
{
	struct process *p = (struct process *)w;

	struct thread *thr;
	bool running;

	for (thr = p->head_thread; thr; thr = thr->next) {
		running = !thr_is_stopped(thr);

		if (running)
			pause_child(thr);
		if (ptrace(PTRACE_POKEUSER, thr->pid,
			   offsetof(u_debugreg[7], struct user),
			   0) < 0)
			err(1, "Clearing debug register 7 of %d", thr->pid);
		if (running)
			unpause_child(thr);
	}
}

void
get_regs(struct thread *thr, struct user_regs_struct *urs)
{
	assert(thr_is_stopped(thr));
	if (ptrace(PTRACE_GETREGS, thr->pid, NULL, urs) < 0)
		err(1, "PTRACE_GETREGS(%d)", thr->pid);
}

#ifdef VERY_LOUD
static void
show_regs_delta(const struct user_regs_struct *from,
		const struct user_regs_struct *to)
{
#define do_reg(rname)							\
	if (from-> rname != to-> rname)					\
		msg(1, #rname ": %lx -> %lx ", from-> rname,		\
		    to-> rname)
	do_reg(r15);
	do_reg(r14);
	do_reg(r13);
	do_reg(r12);
	do_reg(r11);
	do_reg(r10);
	do_reg(r9);
	do_reg(r8);
	do_reg(rax);
	do_reg(rcx);
	do_reg(rdx);
	do_reg(rbx);
	do_reg(rsp);
	do_reg(rbp);
	do_reg(rsi);
	do_reg(rdi);
	do_reg(orig_rax);
	do_reg(rip);
	do_reg(cs);
	do_reg(eflags);
	do_reg(ss);
	do_reg(fs_base);
	do_reg(gs_base);
	do_reg(ds);
	do_reg(es);
	do_reg(fs);
	do_reg(gs);
#undef do_reg
}
#endif /* VERY_LOUD */

void
set_regs(struct thread *thr, const struct user_regs_struct *urs)
{
#ifdef VERY_LOUD
	struct user_regs_struct urs2;
	get_regs(thr, &urs2);
	msg(1, "%d: ", thr->pid);
	show_regs_delta(&urs2, urs);
	msg(1, "\n");
#endif /* VERY_LOUD */
	assert(thr_is_stopped(thr));
	if (ptrace(PTRACE_SETREGS, thr->pid, NULL, urs))
		err(1, "PTRACE_SETREGS(%d)", thr->pid);
}

void
handle_breakpoint(struct thread *thr)
{
	struct user_regs_struct urs;
	struct breakpoint *bp;
	siginfo_t si;

	if (ptrace(PTRACE_GETSIGINFO, thr->pid, NULL, &si) < 0)
		err(1, "PTRACE_GETSIGINFO2(%d)", thr->pid);
	if (si.si_code == TRAP_HWBKPT) {
		/* It's a watchpoint.  This can happen due to some races in
		   the way we clear watchpoints; just ignore it. */
		resume_child(thr);
		return;
	}

	get_regs(thr, &urs);
	urs.rip -= 1;
	for (bp = thr->process->head_breakpoint; bp; bp = bp->next) {
		if (bp->addr == urs.rip) {
			bp->f(thr, bp, bp->ctxt, &urs);
			resume_child(thr);
			return;
		}
	}

	/* This can happen if a thread hits a breakpoint, but we clear
	   the breakpoint before we notice that it stopped.  Ignore
	   it. */
	msg(5, "... not one of our breakpoints at %lx...\n", urs.rip);

	set_regs(thr, &urs);
	resume_child(thr);
}

