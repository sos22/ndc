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

#define offsetof(field, strct) ((unsigned long)&((strct *)0)->field)

/* Annoyingly, the glibc headers don't include this, and it's hard to
   get the kernel ones to play nicely with the glibc ones.  Use the
   glibc ones and suplement with this one #define from the kernel
   headers. */
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif

#define PRELOAD_LIB_NAME "./ndc.so"
#define PTRACE_OPTIONS \
	(PTRACE_O_TRACEFORK |			\
	 PTRACE_O_TRACEVFORK |			\
	 PTRACE_O_TRACECLONE |			\
	 PTRACE_O_TRACEEXEC |			\
	 PTRACE_O_TRACEVFORKDONE)

static const char *target_binary;

struct process;
struct loaded_object;
struct thread;

struct breakpoint {
	struct breakpoint *next;
	struct breakpoint *prev;

	struct breakpoint *next_lo;
	struct breakpoint *prev_lo;

	struct loaded_object *lo;

	unsigned long addr;
	unsigned char old_content;
	void (*f)(struct thread *, struct breakpoint *, void *ctxt,
		  struct user_regs_struct *urs);
	void *ctxt;
};

struct loaded_object {
	struct loaded_object *next;
	struct loaded_object *prev;
	struct breakpoint *head_bp;
	char *name;
	bool live;

	unsigned nr_instrs_alloced;
	unsigned nr_instrs;
	unsigned long *instrs;
};

struct thread {
	struct thread *next, *prev;
	struct process *process;
	pid_t pid;

	int stop_status; /* from wait(), or -1 if it's currently
			  * running */
};

/* Arggh... When a child clone()s itself, we need to process the
   ptrace event from the parent *before* the SIGSTOP in the child, but
   they sometimes get reordered.  Use a staging buffer. */
struct pending_wait_status {
	unsigned nr_pending;
	unsigned nr_allocated;
	struct {
		int status;
		pid_t pid;
	} *pending;
};

struct process {
	struct thread *head_thread;
	int from_child_fd;
	int to_child_fd;
	unsigned long linker_brk_addr;
	int nr_threads;
	int tgid;

	pid_t timeout_pid;
	bool timeout_fired;

	struct breakpoint *head_breakpoint;
	struct loaded_object *head_loaded_object;

	struct pending_wait_status pws;
};

/* An x86 instruction consists of

   -- Some prefixes
   -- One or two bytes of opcode
   -- An optional modrm,sib,disp complex
   -- Some bytes of immediate data

   The template gives you the breakdown of the instruction into those
   bytes, and also tells you the type of modrm which is in use (read,
   write, no-access, etc.)

   Prefixes should really be divided into legacy and REX blocks, where
   there is at most one REX prefix, but we don't bother.
*/
struct instr_template {
	int bytes_prefix;
	int bytes_opcode;
	int bytes_modrm; /* includes SIB and displacement, if present */
	int bytes_immediate;
	int modrm_access_type;
};

static unsigned
instr_size(const struct instr_template *it)
{
	return it->bytes_prefix + it->bytes_opcode + it->bytes_modrm + it->bytes_immediate;
}

static unsigned long
fetch_ulong(struct thread *thr, unsigned long addr)
{
	unsigned long buf;
	assert(thr->stop_status != -1);
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
static int
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

	assert(thr->stop_status != -1);
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
	assert(thr->stop_status != -1);
	if (ptrace(PTRACE_POKEDATA, thr->pid, addr, ulong) < 0)
		err(1, "poke(%lx, %lx)", addr, ulong);
}

static void
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

static struct breakpoint *
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

static void
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
	}

	free(bp);
}

static int
tgkill(int tgid, int tid, int sig)
{
	return syscall(__NR_tgkill, tgid, tid, sig);
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
			thr->stop_status = proc->pws.pending[x].status;
			printf("Pick up pending %x for pid %d\n",
			       thr->stop_status, thr->pid);
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

static bool
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
	if (thr) {
		thr->stop_status = status;
	} else {
		printf("Push to pending\n");
		push_pending_wait_status(&proc->pws, pid, status);
	}

	return true;
}

static bool
pause_child(struct thread *thr)
{
	if (thr->stop_status != -1)
		return true;
	if (tgkill(thr->process->tgid, thr->pid, SIGSTOP) < 0)
		err(1, "kill(SIGSTOP)");
	while (thr->stop_status == -1)
		if (!receive_ptrace_event(thr->process))
			return false;
	return true;
}

static void
resume_child(struct thread *thr)
{
	if (thr->stop_status == -1)
		return;
	if (ptrace(PTRACE_CONT, thr->pid, NULL, NULL) < 0)
		err(1, "ptrace(PTRACE_CONT) from resume_child()");
	thr->stop_status = -1;
}

static void
unpause_child(struct thread *thr)
{
	if (WIFSTOPPED(thr->stop_status) && WSTOPSIG(thr->stop_status) == SIGSTOP)
		resume_child(thr);
}

/* Only need one at a time, so this is trivial. */
struct watchpoint {
};

static struct watchpoint *
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
		running = thr->stop_status == -1;
		if (running)
			pause_child(thr);

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

static void
unset_watchpoint(struct watchpoint *w)
{
	struct process *p = (struct process *)w;

	struct thread *thr;
	bool running;

	for (thr = p->head_thread; thr; thr = thr->next) {
		running = thr->stop_status == -1;

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

static void
get_regs(struct thread *thr, struct user_regs_struct *urs)
{
	assert(thr->stop_status != -1);
	if (ptrace(PTRACE_GETREGS, thr->pid, NULL, urs) < 0)
		err(1, "PTRACE_GETREGS()");
}

static void
handle_breakpoint(struct thread *thr)
{
	struct user_regs_struct urs;
	struct breakpoint *bp;

	get_regs(thr, &urs);
	urs.rip -= 1;
	printf("Breakpoint at %lx\n", urs.rip);
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
	printf("... not one of our breakpoints at %lx...\n", urs.rip);
	resume_child(thr);
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
	thr->stop_status = -1;
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

	while (thr->stop_status == -1)
		if (!receive_ptrace_event(work))
			abort();
	if (!WIFSTOPPED(thr->stop_status) || WSTOPSIG(thr->stop_status) != SIGTRAP)
		errx(1, "strange status %x from waitpid()", thr->stop_status);

	/* Turn on basically all the options except TRACESYSGOOD */
	if (ptrace(PTRACE_SETOPTIONS,
		   thr->pid,
		   NULL,
		   PTRACE_OPTIONS) < 0)
		err(1, "ptrace(PTRACE_SETOPTIONS)");

	return work;
}

static void
add_mem_access_instr(struct loaded_object *lo, unsigned long addr)
{
	printf("Access at %lx\n", addr);
	if (lo->nr_instrs == lo->nr_instrs_alloced) {
		lo->nr_instrs_alloced *= 3;
		lo->instrs = realloc(lo->instrs, sizeof(lo->instrs[0]) * lo->nr_instrs_alloced);
	}
	lo->instrs[lo->nr_instrs] = addr;
	lo->nr_instrs++;
}

#define PFX_REX_0         0
#define PFX_REX_W         1
#define PFX_REX_R         2
#define PFX_REX_X         3
#define PFX_REX_B         4
#define PFX_OPSIZE        5
#define PFX_ADDRSIZE      6
#define PFX_CS            8
#define PFX_DS            9
#define PFX_ES           10
#define PFX_FS           11
#define PFX_GS           12
#define PFX_SS           13
#define PFX_LOCK         14
#define PFX_REP          15
#define PFX_REPN         16

/* Invalid -> there is no modrm, none -> there is a modrm but it's not
 * used to access memory */
#define ACCESS_INVALID 0
#define ACCESS_R 1
#define ACCESS_W 2
#define ACCESS_RW 3
#define ACCESS_NONE 4

static void
modrm(const unsigned char *instr,
      struct instr_template *it,
      unsigned long mapped_at,
      struct loaded_object *lo,
      unsigned prefixes)
{
	unsigned char modrm = instr[it->bytes_prefix + it->bytes_opcode];
	unsigned rm = modrm & 7;
	unsigned mod = modrm >> 6;
	int interesting = it->modrm_access_type != ACCESS_NONE;

	if (mod == 3) {
		/* Register -> not interesting */
		interesting = 0;
	} else if (rm == 4 && !(prefixes & (1 << PFX_REX_B))) {
		unsigned base = instr[it->bytes_prefix + it->bytes_opcode + 1] & 7;
		if (base == 4) {
			/* Stack access -> not interesting */
			interesting = 0;
		}
	}

	if (interesting)
		add_mem_access_instr(lo, mapped_at);
}

static void
find_instr_template(const unsigned char *instr,
		    unsigned long addr,
		    struct instr_template *it,
		    unsigned *prefixes)
{
	unsigned opcode;
	unsigned imm_opsize;

	memset(it, 0, sizeof(*it));

	it->modrm_access_type = ACCESS_INVALID;
	*prefixes = 0;

	while (1) {
		it->bytes_prefix++;
		switch (instr[it->bytes_prefix-1]) {
		case 0x26:
			*prefixes |= 1 << PFX_ES;
			break;
		case 0x2e:
			*prefixes |= 1 << PFX_CS;
			break;
		case 0x36:
			*prefixes |= 1 << PFX_SS;
			break;
		case 0x3e:
			*prefixes |= 1 << PFX_DS;
			break;
		case 0x64:
			*prefixes |= 1 << PFX_FS;
			break;
		case 0x65:
			*prefixes |= 1 << PFX_GS;
			break;
		case 0x66:
			*prefixes |= 1 << PFX_OPSIZE;
			break;
		case 0x67:
			*prefixes |= 1 << PFX_ADDRSIZE;
			break;
		case 0xF0:
			*prefixes |= 1 << PFX_LOCK;
			break;
		case 0xF2:
			*prefixes |= 1 << PFX_REPN;
			break;
		case 0xF3:
			*prefixes |= 1 << PFX_REP;
			break;
		default:
			goto done_prefixes;
		}
	}
done_prefixes:
	it->bytes_prefix--;

	if (instr[it->bytes_prefix] >= 0x40 && instr[it->bytes_prefix] <= 0x4f) {
		*prefixes |= 1 << PFX_REX_0;
		if (instr[it->bytes_prefix] & 1)
			*prefixes |= 1 << PFX_REX_B;
		if (instr[it->bytes_prefix] & 2)
			*prefixes |= 1 << PFX_REX_X;
		if (instr[it->bytes_prefix] & 4)
			*prefixes |= 1 << PFX_REX_R;
		if (instr[it->bytes_prefix] & 8)
			*prefixes |= 1 << PFX_REX_W;
		it->bytes_prefix++;
	}

	imm_opsize = 4;
	if (*prefixes & (1 << PFX_OPSIZE))
		imm_opsize = 2;

	it->bytes_opcode = 1;
	opcode = instr[it->bytes_prefix];
	if (opcode <= 0x37 && ((opcode & 7) <= 5)) {
		/* These are simple arithmetic operations.  Handle
		 * them seperately */
		switch (opcode & 7) {
		case 0: case 1: /* <op> Ex, Gx */
			it->modrm_access_type = ACCESS_RW;
			break;
		case 2: case 3: /* <op> Gx, Ex */
			it->modrm_access_type = ACCESS_R;
			break;
		case 4: /* <op> al, Ib */
			it->bytes_immediate = 1;
			break;
		case 5: /* <op> al, Iz */
			it->bytes_immediate = imm_opsize;
			break;
		}
		goto done_decode;
	}
	switch (opcode) {
	case 0x0f: /* Escape to two-byte */
		it->bytes_opcode = 2;
		switch (instr[it->bytes_prefix + 1]) {
		case 0x1f: /* nop */
			it->modrm_access_type = ACCESS_NONE;
			break;

		case 0x80 ... 0x8f: /* jcc Jz */
			it->bytes_immediate = 4;
			break;

		case 0x10: /* movss Vss, Wss */

		case 0x14:
		case 0x28 ... 0x2a: /* Various XMM instructions */
		case 0x2c ... 0x2f:
		case 0x51 ... 0x5f:

		case 0x40 ... 0x4f: /* cmovcc Gv, Ev */
		case 0xaf: /* imul Gv, Ev */
		case 0xb6: /* movz Gv, Eb */
		case 0xb7: /* movz Gv, Ew */
		case 0xbd: /* bsr Gv, Ev */
		case 0xbe: /* movsz Gb, Eb */
		case 0xbf: /* movsz Gb, Ew */
			it->modrm_access_type = ACCESS_R;
			break;

		case 0xd6:
			if (*prefixes & (1 << PFX_OPSIZE))
				it->modrm_access_type = ACCESS_W;
			else
				it->modrm_access_type = ACCESS_R;
			break;

		case 0x7e: /* Movd with mode one of Ed/q, Pd/q; Vq, Wq; Ed/q, Vd/q */
			if (*prefixes & (1 << PFX_REP))
				it->modrm_access_type = ACCESS_R;
			else
				it->modrm_access_type = ACCESS_W;
			break;

		case 0x11:
		case 0x90 ... 0x9f: /* setne */
			it->modrm_access_type = ACCESS_W;
			break;

		case 0xc1: /* xadd Ev, Gv */
			it->modrm_access_type = ACCESS_RW;
			break;

		case 0xc2:
			it->modrm_access_type = ACCESS_R;
			it->bytes_immediate = 1;
			break;

		default:
			errx(1, "Can't handle instruction %02x %02x at %#lx\n",
			     instr[it->bytes_prefix], instr[it->bytes_prefix+1],
			     addr);
		}
		break;

	case 0x3c: /* cmp al, Ib */
	case 0x70 ... 0x7f: /* jcc Ib */
	case 0xa8: /* test al, Ib */
	case 0xb0 ... 0xb7: /* mov reg, Ib */
	case 0xeb: /* jmp Ib */
		it->bytes_immediate = 1;
		break;

	case 0xd0 ... 0xd3: /* group 2 E{bv}, {1,Cl} */
		it->modrm_access_type = ACCESS_RW;
		break;

	case 0xd8 ... 0xdf: /* x87 */ {
		unsigned modrm = instr[it->bytes_prefix + 1];
		if (modrm > 0xc0) {
			/* This instruction doesn't access memory, but
			   has a one-byte pseudo-modrm.  Treat it as
			   part of the opcode. */
			it->modrm_access_type = ACCESS_INVALID;
			it->bytes_opcode = 2;
		} else {
			/* Access memory, need to be slightly more
			 * careful */
			unsigned reg = (modrm >> 3) & 7;
			it->modrm_access_type = ACCESS_R;
			if (opcode == 0xd9) {
				if (reg == 2 || reg == 3 ||
				    reg == 6 || reg == 7)
					it->modrm_access_type = ACCESS_W;
			} else if (opcode & 1) {
				if (reg != 0 && reg != 5)
					it->modrm_access_type = ACCESS_W;
			}
		}
		break;
	}

	case 0x69: /* imul Gv, Ev, Iz */
		it->modrm_access_type = ACCESS_R;
		it->bytes_immediate = imm_opsize;
		break;

	case 0x80: /* Group 1 Eb, Ib */
	case 0x81: /* Group 1 Ev, Iz */
	case 0x83: /* Group 1 Ev, Ib */
		if ( ((instr[it->bytes_prefix+1] >> 3) & 7) == 7) {
			/* cmp instruction */
			it->modrm_access_type = ACCESS_R;
		} else {
			it->modrm_access_type = ACCESS_RW;
		}
		if (instr[it->bytes_prefix] == 0x80 || instr[it->bytes_prefix] == 0x83)
			it->bytes_immediate = 1;
		else
			it->bytes_immediate = imm_opsize;
		break;

	case 0xc0: /* Group 2 Eb, Ib */
	case 0xc1: /* Group 2 Ev, Ib */
		it->bytes_immediate = 1;
		it->modrm_access_type = ACCESS_RW;
		break;

	case 0x88: /* mov Eb, Gb */
	case 0x89: /* mov Ev, Gv */
		it->modrm_access_type = ACCESS_W;
		break;

	case 0xc6: /* group 11 Eb, Ib */
		it->bytes_immediate = 1;
		it->modrm_access_type = ACCESS_W;
		break;

	case 0xc7: /* group 11 Ev, Iz */
		it->bytes_immediate = imm_opsize;
		it->modrm_access_type = ACCESS_W;
		break;

	case 0x38 ... 0x3b: /* Various forms of cmp */
	case 0x63: /* mov Gv, Ed */
	case 0x84: /* test Ev, Gv */
	case 0x85: /* test Ev, Gv */
	case 0x8a: /* mov Gb, Eb */
	case 0x8b: /* mov Gv, Ev */
	case 0xff: /* Group 5 Ev */
		it->modrm_access_type = ACCESS_R;
		break;

	case 0x8d: /* lea Gv, M */
		it->modrm_access_type = ACCESS_NONE;
		break;

	case 0x50 ... 0x5f: /* push and pop single register */
	case 0x90: /* nop */
	case 0x98: /* cltq */
	case 0xc3: /* ret */
	case 0xc9: /* leave */
	case 0xf4: /* hlt */

	case 0xa6: /* cmps.  This does access memory, but it's in a
		      moderately hard-to-handle way, so just ignore
		      it. */
	case 0xab: /* stos */
	case 0xa5: /* movs */
		break;

	case 0x3d: /* cmp rax, Iz */
	case 0x68: /* push Iz */
	case 0xa9: /* test rax, Iz */
	case 0xe8: /* Call Jz */
	case 0xe9: /* jmp Jz */
		it->bytes_immediate = imm_opsize;
		break;

	case 0xb8 ... 0xbf: /* mov reg, Iz */
		if (*prefixes & (1 << PFX_REX_W))
			it->bytes_immediate = 8;
		else if (*prefixes & (1 << PFX_OPSIZE))
			it->bytes_immediate = 2;
		else
			it->bytes_immediate = imm_opsize;
		break;

	case 0xf6:
	case 0xf7: /* group 3 */ {
		unsigned modrm = instr[it->bytes_prefix+1];
		unsigned reg = (modrm >> 3) & 7;
		if (reg == 0 || reg == 1) {
			/* test Ev, Iz */
			if (opcode == 0xf7)
				it->bytes_immediate = imm_opsize;
			else
				it->bytes_immediate = 1;
		} else {
			/* Other Ev */
			it->bytes_immediate = 0;
		}
		it->modrm_access_type = ACCESS_R;
		break;
	}

	default:
		errx(1, "Can't handle instruction byte %02x at %#lx", instr[it->bytes_prefix],
		     addr);
	}

done_decode:

	/* If we have a modrm, figure out how big it is. */
	if (it->modrm_access_type != ACCESS_INVALID) {
		unsigned char modrm = instr[it->bytes_prefix + it->bytes_opcode];
		unsigned rm = modrm & 7;
		unsigned mod = modrm >> 6;

		it->bytes_modrm = 1;
		if (mod == 3) {
			/* Register encoding -> no SIB or displacement */
		} else {
			if (rm == 4) {
				/* SIB */
				it->bytes_modrm++;
				if (mod == 0 &&
				    (instr[it->bytes_prefix + it->bytes_opcode + 1] & 7) == 5) {
					/* disp32 */
					it->bytes_modrm += 4;
				}
			}
			if (mod == 1) {
				/* disp8 */
				it->bytes_modrm++;
			} else if (mod == 2) {
				/* disp32 */
				it->bytes_modrm += 4;
			} else if (rm == 5) {
				assert(mod == 0);
				/* RIP relative 32 bit */
				it->bytes_modrm += 4;
			}
		}
	}
}

static unsigned
handle_instruction(const unsigned char *base,
		   const unsigned char *instr,
		   unsigned long mapped_at,
		   struct loaded_object *lo)
{
	unsigned prefixes;
	struct instr_template it;
	find_instr_template(instr, mapped_at, &it, &prefixes);
	if (it.modrm_access_type != ACCESS_INVALID)
		modrm(instr, &it, mapped_at, lo, prefixes);
	return instr_size(&it);
}

static unsigned long
fetch_reg_by_index(const struct user_regs_struct *urs, unsigned index)
{
#define c(i, n) case i: return urs-> n
	switch (index) {
		c(0, rax);
		c(1, rcx);
		c(2, rdx);
		c(3, rbx);
		c(4, rsp);
		c(5, rbp);
		c(6, rsi);
		c(7, rdi);
#define c2(i) c(i, r ## i)
		c2(8);
		c2(9);
		c2(10);
		c2(11);
		c2(12);
		c2(13);
		c2(14);
		c2(15);
#undef c2
#undef c
	default:
		fprintf(stderr, "bad register index %d\n", index);
		abort();
	}
}

static unsigned long
eval_modrm_addr(const unsigned char *modrm_bytes,
		const struct instr_template *it,
		unsigned prefixes,
		const struct user_regs_struct *urs)
{
	unsigned modrm = modrm_bytes[0];
	unsigned rm = modrm & 7;
	unsigned mod = modrm >> 6;
	const unsigned char *disp_bytes;
	unsigned long reg;

	assert(mod != 3);
	if (rm == 4) {
		/* SIB */
		unsigned sib;
		unsigned base;
		unsigned index;
		unsigned scale;
		unsigned long sibval;

		disp_bytes = modrm_bytes + 2;

		sib = modrm_bytes[1];
		base = sib & 7;
		index = (sib >> 3) & 7;
		scale = 1 << (sib >> 6);

		if (prefixes & (1 << PFX_REX_B))
			base |= 8;
		if (base == 5 || base == 13) {
			if (mod == 0) {
				sibval = (long)*(int *)disp_bytes;
			} else if (mod == 1) {
				sibval = fetch_reg_by_index(urs, base) +
					*(char *)disp_bytes;
			} else {
				sibval = fetch_reg_by_index(urs, base) +
					*(int *)disp_bytes;
			}
		} else {
			sibval = fetch_reg_by_index(urs, base);
		}
		if (prefixes & (1 << PFX_REX_X))
			index |= 8;
		if (index != 4)
			sibval += fetch_reg_by_index(urs, index) * scale;

		return sibval;
	}

	disp_bytes = modrm_bytes + 1;

	reg = fetch_reg_by_index(
		urs,
		rm | (prefixes & (1 << PFX_REX_B) ? 8 : 0));

	switch (mod) {
	case 0:
		if (rm == 5)
			return urs->rip + instr_size(it) + *(int *)disp_bytes;
		else
			return reg;
	case 1:
		return reg + *(char *)disp_bytes;
	case 2:
		return reg + *(int *)disp_bytes;
	}
	abort();
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
memory_access_breakpoint(struct thread *p, struct breakpoint *bp, void *ctxt,
			 struct user_regs_struct *urs)
{
	unsigned char instr[16];
	unsigned prefixes;
	struct instr_template it;
	unsigned long modrm_addr;
	struct watchpoint *wp;
	struct itimerval itimer;

	/* No longer need this breakpoint. */
	unset_breakpoint(p, bp);
	if (ptrace(PTRACE_SETREGS, p->pid, NULL, urs) < 0)
		err(1, "PTRACE_SETREGS");

	if (p->process->nr_threads == 1)
		return;

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

	printf("%lx: Access %lx %c%c\n",
	       urs->rip,
	       modrm_addr,
	       it.modrm_access_type & ACCESS_R ? 'r' : '.',
	       it.modrm_access_type & ACCESS_W ? 'w' : '.');

	if (it.modrm_access_type == ACCESS_R)
		wp = set_watchpoint(p->process, modrm_addr, 8, 0);
	else
		wp = set_watchpoint(p->process, modrm_addr, 8, 1);

	timer_fired = false;

	memset(&itimer, 0, sizeof(itimer));
	itimer.it_value.tv_sec = 1;
	itimer.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &itimer, NULL);

	while (!timer_fired) {
		struct thread *other;
		bool nothing_running = true;
		if (!receive_ptrace_event(p->process))
			continue;
		for (other = p->process->head_thread;
		     other;
		     other = other->next) {
			if (other == p)
				continue;
			if (other->stop_status == -1) {
				nothing_running = false;
				continue;
			}
			if (WIFSTOPPED(other->stop_status) &&
			    WSTOPSIG(other->stop_status) == SIGTRAP) {
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
			memset(&itimer, 0, sizeof(itimer));
			setitimer(ITIMER_REAL, &itimer, NULL);
			break;
		}
	}

	printf("Unsetting watchpoints.\n");
	unset_watchpoint(wp);

	/* XXX set another breakpoint at random */
}

static void
install_breakpoints(struct thread *thr, struct loaded_object *lo)
{
	unsigned nr_breakpoints;
	struct breakpoint *bp;
	/* For now, breakpoint on every memory access */
	unsigned x;
	nr_breakpoints = lo->nr_instrs;

	for (x = 0; x < nr_breakpoints; x++) {
		bp = set_breakpoint(thr, lo->instrs[x], lo, memory_access_breakpoint, lo);
		if (lo->head_bp)
			lo->head_bp->prev_lo = bp;
		bp->next_lo = lo->head_bp;
		lo->head_bp = bp;
	}
}

static void
process_shlib(struct process *p, unsigned long start_vaddr,
	      unsigned long end_vaddr, unsigned long offset,
	      const char *fname)
{
	struct loaded_object *lo;
	int fd;
	ssize_t s;
	const Elf64_Ehdr *hdr;
	bool relocated;
	int nr_shdrs;
	const Elf64_Shdr *shdrs;
	const void *shstrtab;
	const void *current_instr;
	const void *end_instr;
	unsigned x;

	for (lo = p->head_loaded_object; lo && strcmp(lo->name, fname); lo = lo->next)
		;
	if (lo) {
		lo->live = true;
		return;
	}

	printf("%lx %s\n", start_vaddr - offset, fname);
	lo = calloc(sizeof(*lo), 1);
	lo->name = strdup(fname);
	lo->nr_instrs_alloced = 128;
	lo->nr_instrs = 0;
	lo->instrs = calloc(sizeof(lo->instrs[0]), lo->nr_instrs_alloced);
	lo->next = p->head_loaded_object;
	lo->live = true;
	if (p->head_loaded_object)
		p->head_loaded_object->prev = lo;
	p->head_loaded_object = lo;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "opening %s", fname);
	s = lseek(fd, 0, SEEK_END);
	if (s < 0)
		err(1, "finding size of %s", fname);

	s = (s + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	hdr = mmap(NULL, s, PROT_READ, MAP_PRIVATE, fd, 0);
	if (hdr == MAP_FAILED)
		err(1, "mmap() %s", fname);
	close(fd);

	if (hdr->e_ident[0] != 0x7f ||
	    hdr->e_ident[1] != 'E' ||
	    hdr->e_ident[2] != 'L' ||
	    hdr->e_ident[3] != 'F' ||
	    (hdr->e_type != ET_DYN && hdr->e_type != ET_EXEC) ||
	    hdr->e_shentsize != sizeof(Elf64_Shdr))
		errx(1, "%s isn't a valid ELF DSO", fname);
	relocated = hdr->e_type == ET_DYN;
	nr_shdrs = hdr->e_shnum;
	if (nr_shdrs == 0) {
		warnx("%s has no section headers?", fname);
		return;
	}
	shdrs = (void *)hdr + hdr->e_shoff;
	if (hdr->e_shstrndx == 0 || hdr->e_shstrndx > nr_shdrs)
		shstrtab = NULL;
	else
		shstrtab = (void *)hdr + shdrs[hdr->e_shstrndx].sh_offset;

	for (x = 0; x < nr_shdrs; x++) {
		if (shdrs[x].sh_type != SHT_PROGBITS ||
		    !(shdrs[x].sh_flags & SHF_ALLOC) ||
		    !(shdrs[x].sh_flags & SHF_EXECINSTR))
			continue;
		current_instr = (void *)shdrs[x].sh_addr + (unsigned long)hdr - start_vaddr;
		end_instr = current_instr + shdrs[x].sh_size;
		while (current_instr < end_instr) {
			current_instr += handle_instruction(
				(const unsigned char *)hdr,
				current_instr,
				start_vaddr + ((unsigned long)current_instr - (unsigned long)hdr),
				lo);
		}
	}

	install_breakpoints(p->head_thread, lo);

	munmap((void *)hdr, s);
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
		    shlib_interesting(fname2))
			process_shlib(p, start, end, offset, fname2);

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

static void
handle_clone(struct thread *parent)
{
	struct thread *thr;
	unsigned long new_pid;
	int status;
	int x;
	struct pending_wait_status *pws = &parent->process->pws;

	if (ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &new_pid) < 0)
		err(1, "PTRACE_GETEVENTMSG() for clone");
	printf("New pid %ld\n", new_pid);
	thr = calloc(sizeof(*thr), 1);
	thr->pid = new_pid;
	thr->process = parent->process;

	for (x = 0; x < pws->nr_pending; x++) {
		if (pws->pending[x].pid == thr->pid) {
			/* The STOP has already been reported by the
			   kernel.  Use the stashed value. */
			status = pws->pending[x].status;
			memmove(pws->pending + x,
				pws->pending + x + 1,
				sizeof(pws->pending[0]) & (pws->nr_pending - x - 1));
			pws->nr_pending--;
			goto done_wait;
		}
	}
	if (waitpid(thr->pid, &status, __WALL) < 0)
		err(1, "waitpid() for new thread %d", thr->pid);

done_wait:
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
	printf("Child break %lx\n", child->linker_brk_addr);
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
		sleep(5);
		_exit(0);
	}

	while (1) {
		struct thread *thr;

		if (child->timeout_fired) {
			int status;
			struct loaded_object *lo;

			printf("TIMEOUT\n");

			child->timeout_fired = false;
			child->timeout_pid = fork();
			if (child->timeout_pid == 0) {
				sleep(5);
				_exit(0);
			}

			status = child->head_thread->stop_status;
			if (status == -1)
				pause_child(child->head_thread);

			for (lo = child->head_loaded_object; lo; lo = lo->next)
				install_breakpoints(child->head_thread, lo);

			if (status == -1)
				unpause_child(child->head_thread);
		}

		for (thr = child->head_thread; thr && thr->stop_status == -1; thr = thr->next)
			;
		if (!thr) {
			receive_ptrace_event(child);
			continue;
		}

		printf("%d: Stop status %x\n", thr->pid, thr->stop_status);
		if (WIFEXITED(thr->stop_status)) {
			printf("Child exited with status %d, doing the same thing\n",
			       WEXITSTATUS(thr->stop_status));
			thread_exited(thr, WEXITSTATUS(thr->stop_status));
		} else if (WIFSIGNALED(thr->stop_status)) {
			printf("Child got signal %d\n", WTERMSIG(thr->stop_status));
			/* Should arguably raise() the signal here,
			   rather than exiting, so that our parent
			   gets the right status, but that might cause
			   us to dump core, which would potentially
			   obliterate any core dump left behind by the
			   child. */
			exit(1);
		} else if (WIFSTOPPED(thr->stop_status) &&
			   WSTOPSIG(thr->stop_status) == SIGTRAP) {
			switch (thr->stop_status >> 16) {
			case 0:
				handle_breakpoint(thr);
				break;
			case PTRACE_EVENT_CLONE:
				printf("Child spawned a new thread...\n");
				handle_clone(thr);
				break;
			default:
				fprintf(stderr, "unknown ptrace event %d\n", thr->stop_status >> 16);
				abort();
			}
		} else if (WIFSTOPPED(thr->stop_status) &&
			   WSTOPSIG(thr->stop_status) == SIGSTOP) {
			/* Sometimes get these spuriously when
			 * attaching to a new thread or as a resule of
			 * pause_thread().  Ignore. */
			printf("...sigstop...\n");
			resume_child(thr);
		} else {
			fprintf(stderr, "unexpected waitpid status %x\n", thr->stop_status);
			if (WIFSTOPPED(thr->stop_status))
				fprintf(stderr, "... stopped by %d\n", WSTOPSIG(thr->stop_status));
			abort();
		}
	}
	return 0;
}

