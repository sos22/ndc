#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
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

#define PRELOAD_LIB_NAME "./ndc.so"

struct process;
struct loaded_object;

struct breakpoint {
	struct breakpoint *next;
	struct breakpoint *prev;

	struct breakpoint *next_lo;
	struct breakpoint *prev_lo;

	struct loaded_object *lo;

	unsigned long addr;
	unsigned char old_content;
	void (*f)(struct process *, struct breakpoint *, void *ctxt,
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

struct process {
	pid_t pid;
	int from_child_fd;
	int to_child_fd;
	unsigned long linker_brk_addr;
	bool running;
	struct breakpoint *head_breakpoint;
	struct loaded_object *head_loaded_object;
};

static unsigned long
fetch_ulong(struct process *proc, unsigned long addr)
{
	unsigned long buf;
	errno = 0;
	buf = ptrace(PTRACE_PEEKDATA, proc->pid, addr);
	if (errno != 0)
		err(1, "peek(%lx)", addr);
	return buf;
}

static unsigned char
fetch_byte(struct process *proc, unsigned long addr)
{
	unsigned byte_idx;
	union {
		unsigned long buf;
		unsigned char bytes[8];
	} u;
	byte_idx = addr % 8;
	addr -= byte_idx;
	u.buf = fetch_ulong(proc, addr);
	return u.bytes[byte_idx];
}

static void
store_ulong(struct process *proc, unsigned long addr, unsigned long ulong)
{
	if (ptrace(PTRACE_POKEDATA, proc->pid, addr, ulong) < 0)
		err(1, "poke(%lx, %lx)", addr, ulong);
}

static void
store_byte(struct process *proc, unsigned long addr, unsigned char byte)
{
	unsigned byte_idx;
	union {
		unsigned long buf;
		unsigned char bytes[8];
	} u;
	byte_idx = addr % 8;
	addr -= byte_idx;
	u.buf = fetch_ulong(proc, addr);
	u.bytes[byte_idx] = byte;
	store_ulong(proc, addr, u.buf);
}

static struct breakpoint *
set_breakpoint(struct process *proc, unsigned long addr,
	       struct loaded_object *lo,
	       void (*f)(struct process *, struct breakpoint *, void *ctxt,
			 struct user_regs_struct *urs),
	       void *ctxt)
{
	struct breakpoint *bp = calloc(sizeof(*bp), 1);

	bp->addr = addr;
	bp->f = f;
	bp->ctxt = ctxt;
	bp->next = proc->head_breakpoint;
	bp->lo = lo;
	if (proc->head_breakpoint)
		proc->head_breakpoint->prev = bp;
	proc->head_breakpoint = bp;

	bp->old_content = fetch_byte(proc, addr);
	store_byte(proc, addr, 0xcc);

	return bp;
}

static void
unset_breakpoint(struct process *proc, struct breakpoint *bp)
{
	store_byte(proc, bp->addr, bp->old_content);
	if (bp->next)
		bp->next->prev = bp->prev;
	if (bp->prev)
		bp->prev->next = bp->next;
	else
		proc->head_breakpoint = bp->next;

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

static void
pause_child(struct process *proc)
{
	int status;

	if (!proc->running)
		return;
	if (kill(proc->pid, SIGSTOP) < 0)
		err(1, "kill(SIGSTOP)");
	if (waitpid(proc->pid, &status, WUNTRACED) < 0)
		err(1, "waitpid() after sending SIGSTOP");
	if (WIFSTOPPED(status)) {
		proc->running = false;
		return;
	}

	errx(1, "child stopped for strange reason when sent SIGSTOP: %x", status);
}

static void
resume_child(struct process *proc)
{
	if (proc->running)
		return;
	if (ptrace(PTRACE_CONT, proc->pid, NULL, NULL) < 0)
		err(1, "ptrace(PTRACE_CONT) from resume_child()");
	proc->running = 1;
}

static void
handle_breakpoint(struct process *child)
{
	struct user_regs_struct urs;
	struct breakpoint *bp;

	child->running = false;
	if (ptrace(PTRACE_GETREGS, child->pid, NULL, &urs) < 0)
		err(1, "PTRACE_GETREGS()");
	urs.rip -= 1;
	for (bp = child->head_breakpoint; bp; bp = bp->next) {
		if (bp->addr == urs.rip) {
			bp->f(child, bp, bp->ctxt, &urs);
			resume_child(child);
			return;
		}
	}

	printf("... not one of our breakpoints at %lx...\n", urs.rip);
	if (ptrace(PTRACE_CONT, child->pid, NULL, SIGTRAP) < 0)
		err(1, "PTRACE_CONT() to delivert SIGTRAP");
	child->running = true;
}

/* Invoked as an on_exit handler to do any necessary final cleanup */
static void
kill_child(int ign, void *_child)
{
	struct process *child = _child;
	if (child->pid != 0)
		kill(child->pid, SIGKILL);
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
	int p1[2], p2[2];
	pid_t c2;
	int status;

	work = calloc(sizeof(*work), 1);
	if (pipe(p1) < 0 || pipe(p2) < 0)
		err(1, "pipe()");
	work->pid = fork();
	if (work->pid < 0)
		err(1, "fork()");
	if (work->pid == 0) {
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

	c2 = waitpid(work->pid, &status, 0);
	if (c2 < 0)
		err(1, "waitpid()");
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
		errx(1, "strange status %x from waitpid()", status);

	/* Turn on basically all the options except TRACESYSGOOD */
	if (ptrace(PTRACE_SETOPTIONS,
		   work->pid,
		   NULL,
		   PTRACE_O_TRACEFORK |
		   PTRACE_O_TRACEVFORK |
		   PTRACE_O_TRACECLONE |
		   PTRACE_O_TRACEEXEC |
		   PTRACE_O_TRACEVFORKDONE) < 0)
		err(1, "ptrace(PTRACE_SETOPTIONS)");

	work->running = false;

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

static unsigned
modrm(const unsigned char *instr,
      unsigned bytes_prefix,
      unsigned bytes_opcode,
      unsigned bytes_immediate,
      const void *mapped_at,
      struct loaded_object *lo,
      unsigned prefixes,
      unsigned access)
{
	unsigned char modrm = instr[bytes_prefix + bytes_opcode];
	unsigned rm = modrm & 7;
	unsigned mod = modrm >> 6;
	unsigned char sib;
	unsigned char base;
	unsigned char index;
	unsigned char scale;
	int have_sib = 0;
	unsigned disp = 0;
	int riprel = 0;
	int interesting = access != ACCESS_NONE;

	if (mod == 3) {
		/* Register -> not interesting */
		interesting = 0;
	} else {
		if (rm == 4) {
			have_sib = 1;
			sib = instr[bytes_prefix + bytes_opcode + 1];
			base = sib & 7;
			index = (sib >> 3) & 7;
			scale = sib >> 6;

			if (!(prefixes & (1 << PFX_REX_B)) &&
			    base == 4) {
				/* Stack access -> not interesting */
				interesting = 0;
			}
			if (base == 5) {
				if (mod == 1)
					disp = 1;
				else
					disp = 4;
			}
		}

		if (mod == 0 && rm == 5) {
			disp = 4;
			riprel = 1;
		} else if (mod == 1) {
			disp = 1;
		} else if (mod == 2) {
			disp = 4;
		}
	}

	if (interesting)
		add_mem_access_instr(lo, (unsigned long)mapped_at);

	return 1 + have_sib + disp + bytes_prefix + bytes_opcode + bytes_immediate;
}

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
	int bytes_immediate;
	int modrm_access_type;
};

static void
find_instr_template(const unsigned char *instr,
		    struct instr_template *it,
		    unsigned *prefixes)
{
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

	if (instr[it->bytes_prefix] >= 0x40 && instr[it->bytes_prefix] < 0x4f) {
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

	it->bytes_opcode = 1;

	switch (instr[it->bytes_prefix]) {
	case 0x0f: /* Escape to two-byte */
		it->bytes_opcode = 2;
		switch (instr[it->bytes_prefix + 1]) {
		case 0x1f: /* nop */
			it->modrm_access_type = ACCESS_NONE;
			break;
		case 0x80 ... 0x8f: /* jcc Jz */
			it->bytes_immediate = 4;
			break;
		case 0xb6: /* movz Gv, Eb */
		case 0xb7: /* movz Gv, Ew */
			it->modrm_access_type = ACCESS_R;
			break;
		case 0x90 ... 0x9f: /* setne */
			it->modrm_access_type = ACCESS_W;
			break;
		default:
			errx(1, "Can't handle instruction %02x %02x at %p\n",
			     instr[it->bytes_prefix], instr[it->bytes_prefix+1],
			     instr);
		}
		break;

	case 0x3c: /* cmp al, Ib */
	case 0x70 ... 0x7f: /* jcc Ib */
	case 0xeb: /* jmp Ib */
		it->bytes_immediate = 1;
		break;

	case 0x01: /* add Ev, Gv */
	case 0x29: /* sub Ev, Gv */
	case 0x31: /* xor Ev, Gv */
		it->modrm_access_type = ACCESS_RW;
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
			it->bytes_immediate = 4;
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
		it->bytes_immediate = 4;
		it->modrm_access_type = ACCESS_W;
		break;

	case 0x03: /* add Gv, Ev */
	case 0x38 ... 0x3b: /* Various forms of cmp */
	case 0x63: /* mov Gv, Ed */
	case 0x84: /* test Ev, Gv */
	case 0x85: /* test Ev, Gv */
	case 0x8b: /* mov Gv, Ev */
	case 0xff: /* Group 5 Ev */
		it->modrm_access_type = ACCESS_R;
		break;

	case 0x8d: /* lea Gv, M */
		it->modrm_access_type = ACCESS_NONE;
		break;

	case 0x50 ... 0x5f: /* push and pop single register */
	case 0x90: /* nop */
	case 0xc3: /* ret */
	case 0xc9: /* leave */
	case 0xf4: /* hlt */
		break;

	case 0x05: /* add rax, Iz */
	case 0x25: /* and rax, Iz */
	case 0x2d: /* sub rax, Iz */
	case 0x68: /* push Iz */
	case 0xb8 ... 0xbf: /* mov reg, Iz */
	case 0xe8: /* Call Jz */
	case 0xe9: /* jmp Jz */
		it->bytes_immediate = 4;
		break;

	default:
		errx(1, "Can't handle instruction byte %02x at %p", instr[it->bytes_prefix],
		     instr);
	}
}

static unsigned
handle_instruction(const unsigned char *base,
		   const unsigned char *instr,
		   const void *mapped_at,
		   struct loaded_object *lo)
{
	unsigned prefixes;
	struct instr_template it;

	find_instr_template(instr, &it, &prefixes);

	if (it.modrm_access_type == ACCESS_INVALID)
		return it.bytes_prefix + it.bytes_opcode + it.bytes_immediate;
	return modrm(instr, it.bytes_prefix, it.bytes_opcode, it.bytes_immediate, mapped_at, lo, prefixes, it.modrm_access_type);
}

static void
memory_access_breakpoint(struct process *p, struct breakpoint *bp, void *ctxt,
			 struct user_regs_struct *urs)
{
	printf("Memory access at %lx\n", urs->rip);

	unset_breakpoint(p, bp);

	if (ptrace(PTRACE_SETREGS, p->pid, NULL, urs) < 0)
		err(1, "PTRACE_SETREGS");
}

static void
install_breakpoints(struct process *p, struct loaded_object *lo)
{
	/* For now, breakpoint on every memory access */
	unsigned nr_breakpoints = lo->nr_instrs;
	unsigned x;
	struct breakpoint *bp;

	for (x = 0; x < nr_breakpoints; x++) {
		bp = set_breakpoint(p, lo->instrs[x], lo, memory_access_breakpoint, lo);
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
				(void *)start_vaddr + ((unsigned long)current_instr - (unsigned long)hdr),
				lo);
		}
	}

	install_breakpoints(p, lo);

	munmap((void *)hdr, s);
}

static bool
shlib_interesting(char *fname)
{
	char *f = basename(fname);
	return strcmp(f, "test_dlopen") == 0;
}

static void
unloaded_object(struct process *p, struct loaded_object *lo)
{
	printf("Unloaded %s\n", lo->name);
	while (lo->head_bp)
		unset_breakpoint(p, lo->head_bp);
	if (lo->next)
		lo->next->prev = lo->prev;
	if (lo->prev) {
		lo->prev->next = lo->next;
	} else {
		assert(p->head_loaded_object == lo);
		p->head_loaded_object = lo->next;
	}
	free(lo->name);
	free(lo->instrs);
	free(lo);
}

static void
linker_did_something(struct process *p, struct breakpoint *bp, void *ctxt,
		     struct user_regs_struct *urs)
{
	FILE *f;
	char *path;
	struct loaded_object *lo;

	for (lo = p->head_loaded_object; lo; lo = lo->next)
		lo->live = false;

	asprintf(&path, "/proc/%d/maps", p->pid);
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
		unloaded_object(p, p->head_loaded_object);
		p->head_loaded_object = next;
	}
	if (p->head_loaded_object) {
		struct loaded_object *next;
		for (lo = p->head_loaded_object;
		     lo->next;
		     lo = next) {
			if (!lo->next->live) {
				next = lo->next->next;
				unloaded_object(p, lo->next);
				lo->next = next;
				next = lo;
			} else {
				next = lo->next;
			}
		}
	}

	fclose(f);
}

int
main(int argc, char *argv[], char *environ[])
{
	struct process *child;
	int r;

	child = spawn_child(argv[1], argv + 1);

	/* Child starts stopped. */
	resume_child(child);

	/* Get the break address */
	r = read(child->from_child_fd, &child->linker_brk_addr,
		 sizeof(child->linker_brk_addr));
	if (r != sizeof(child->linker_brk_addr))
		err(1, "reading child's linker break address");
	printf("Child break %lx\n", child->linker_brk_addr);
	pause_child(child);
	set_breakpoint(child, child->linker_brk_addr, NULL,
		       linker_did_something, NULL);
	resume_child(child);

	/* Close out our file descriptors to set it going properly. */
	close(child->from_child_fd);
	close(child->to_child_fd);

	while (1) {
		pid_t c;
		siginfo_t si;

		resume_child(child);
		c = waitid(P_ALL, 0, &si, WEXITED|WSTOPPED);
		if (c < 0)
			err(1, "waitid()");
		assert(si.si_pid == child->pid);

		if (si.si_code == CLD_EXITED) {
			printf("Child exited with status %d, doing the same thing\n",
			       WEXITSTATUS(si.si_status));
			child->pid = 0; /* Keep the on_exit handler
					 * from doing anything
					 * stupid */
			exit(si.si_status);
		} else if (si.si_code == CLD_KILLED) {
			printf("Child got signal %d\n", si.si_status);
			if (si.si_status == SIGSTOP) {
				/* We sometimes send the child
				 * SIGSTOP.  Don't confuse ourselves
				 * when we do so */
				printf("... but we sent it, so it's okay\n");
			} else {
				/* Should arguably raise() the signal
				   here, rather than exiting, so that
				   our parent gets the right status,
				   but that might cause us to dump
				   core, which would potentially
				   obliterate any core dump left
				   behind by the child. */
				exit(1);
			}
		} else if (si.si_code == CLD_TRAPPED) {
			handle_breakpoint(child);
		} else {
			printf("Code %d, status %x\n", si.si_code, si.si_status);
			abort();
		}
	}
	return 0;
}

