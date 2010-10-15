#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <assert.h>
#include <elf.h>
#include <err.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#define PAGE_SIZE 4096ul
#define PAGE_MASK ~(PAGE_SIZE - 1ul)

struct breakpoint {
	struct breakpoint *next, *prev;
	unsigned long addr;
	unsigned char old_content;
	void (*f)(void *ctxt, ucontext_t *uc, struct breakpoint *this);
	void *ctxt;
};

struct loaded_object {
	struct loaded_object *next;
	char *name;
	int live;
	unsigned nr_instrs;
	unsigned nr_instrs_alloced;
	unsigned long *instrs;
	unsigned nr_breakpoints;
	struct breakpoint **breakpoints;
};

static struct breakpoint *
head_breakpoint;
static struct loaded_object *
first_loaded_object;
static const char *
objects_to_examine;

static void scan_link_table(void);


static struct breakpoint *
set_breakpoint(unsigned long addr,
	       void (*f)(void *ctxt, ucontext_t *uc, struct breakpoint *this),
	       void *ctxt)
{
	struct breakpoint *w;
	unsigned long p;

	w = malloc(sizeof(*w));
	w->addr = addr;
	w->f = f;
	w->ctxt = ctxt;
	w->prev = NULL;
	w->old_content = *(unsigned char *)addr;
	w->next = head_breakpoint;
	if (head_breakpoint)
		head_breakpoint->prev = w;
	head_breakpoint = w;

	p = addr & PAGE_MASK;
	if (mprotect((void *)p, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC) < 0)
		return NULL;
	*(unsigned char *)addr = 0xcc;
	if (mprotect((void *)p, PAGE_SIZE, PROT_READ|PROT_EXEC) < 0)
		err(1, "restoring page protections");

	printf("Installed breakpoint at %lx, old %x\n", addr,
		w->old_content);

	return w;
}

static void
clear_breakpoint(struct breakpoint *bp)
{
	unsigned long p = bp->addr & PAGE_MASK;
	if (mprotect((void *)p, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC) < 0)
		err(1, "mprotect(%#lx) to remove BP", p);
	*(unsigned char *)bp->addr = bp->old_content;
	if (mprotect((void *)p, PAGE_SIZE, PROT_READ|PROT_EXEC) < 0)
		err(1, "mprotect(%#lx) to finish removing BP", p);
	/* XXX synchronisation?  The thing might already be running... */
	if (bp->next)
		bp->next->prev = bp->prev;
	if (bp->prev) {
		bp->prev->next = bp->next;
	} else {
		assert(bp == head_breakpoint);
		head_breakpoint = bp->next;
	}
	free(bp);
}

static void
breakpoint_handler(int sig, siginfo_t *si, void *_uc)
{
	ucontext_t *uc = _uc;
	mcontext_t *mc = &uc->uc_mcontext;
	unsigned long rip = mc->gregs[REG_RIP] - 1;
	struct breakpoint *bp;

	for (bp = head_breakpoint;
	     bp && bp->addr != rip;
	     bp = bp->next)
		;
	if (!bp)
		abort();
	bp->f(bp->ctxt, uc, bp);
}

static void
linker_changed_break(void *ign, ucontext_t *uc, struct breakpoint *this)
{
	if (_r_debug.r_state != RT_CONSISTENT)
		return;
	scan_link_table();
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

more_prefixes:
	if (instr[it->bytes_prefix] == 0x66) {
		*prefixes |= 1 << PFX_OPSIZE;
		it->bytes_prefix++;
		goto more_prefixes;
	}

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
			errx(1, "Can't handle instruction %02x %02x\n", instr[it->bytes_prefix], instr[it->bytes_prefix+1]);
		}
		break;

	case 0x3c: /* cmp al, Ib */
	case 0x70 ... 0x7f: /* jcc Ib */
	case 0xeb: /* jmp Ib */
		it->bytes_immediate = 1;
		break;

	case 0x01: /* add Ev, Gv */
	case 0x29: /* sub Ev, Gv */
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
		errx(1, "Can't handle instruction byte %02x\n", instr[it->bytes_prefix]);
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

static unsigned long
fetch_reg_by_index(const mcontext_t *mc, unsigned index)
{
	switch (index) {
	case 0:	return mc->gregs[REG_RAX];
	case 1: return mc->gregs[REG_RCX];
	case 2: return mc->gregs[REG_RDX];
	case 3: return mc->gregs[REG_RBX];
	case 4:	return mc->gregs[REG_RSP];
	case 5: return mc->gregs[REG_RBP];
	case 6: return mc->gregs[REG_RSI];
	case 7: return mc->gregs[REG_RDI];
	default:
		assert(index < 16);
		return mc->gregs[index - 8 + REG_R8];
	}
}

static unsigned long
eval_modrm_addr(const unsigned char *start,
		unsigned prefixes,
		unsigned bytes_immediate,
		const mcontext_t *mc)
{
	unsigned modrm = start[0];
	unsigned rm = modrm & 7;
	unsigned mod = modrm >> 6;
	int have_sib = rm == 4;
	unsigned long sibval;

	assert(mod != 3);
	if (prefixes & (1 << PFX_REX_B))
		rm |= 8;
	if (have_sib) {
		unsigned sib;
		unsigned base;
		unsigned index;
		unsigned scale;

		sib = start[1];
		base = sib & 7;
		index = (sib >> 3) & 7;
		scale = 1 << (sib >> 6);

		if (prefixes & (1 << PFX_REX_B))
			base |= 8;
		if (base == 5 || base == 13) {
			if (mod == 0) {
				sibval = (long)*(int *)(start + 2);
			} else if (mod == 1) {
				sibval = fetch_reg_by_index(mc, base) +
					*(char *)(start + 2);
			} else {
				sibval = fetch_reg_by_index(mc, base) +
					*(int *)(start + 2);
			}
		} else {
			sibval = fetch_reg_by_index(mc, base);
		}
		if (prefixes & (1 << PFX_REX_X))
			index |= 8;
		if (index != 4)
			sibval += fetch_reg_by_index(mc, index) * scale;
	}

	switch (mod) {
	case 0:
		if (have_sib) {
			return sibval;
		} else if (rm == 5 || rm == 13) {
			unsigned long n = (unsigned long)start + bytes_immediate + 5;
			return (unsigned long)n + *(int *)(start + 1);
		} else {
			return fetch_reg_by_index(mc, rm);
		}
	case 1:
		if (have_sib)
			return sibval;
		else
			return fetch_reg_by_index(mc, rm) + *(char *)(start + 1);
	case 2:
		if (have_sib)
			return sibval;
		else
			return fetch_reg_by_index(mc, rm) + *(int *)(start + 1);
	}
	abort();
}

static void
memory_access_breakpoint(void *_lo, ucontext_t *uc, struct breakpoint *this)
{
	struct instr_template it;
	unsigned prefixes;
	unsigned long rip;
	unsigned long modrm_addr;
	//struct loaded_object *lo = _lo;

	uc->uc_mcontext.gregs[REG_RIP]--;
	rip = uc->uc_mcontext.gregs[REG_RIP];
	clear_breakpoint(this);

	find_instr_template((const void *)rip, &it, &prefixes);

	assert(it.modrm_access_type != ACCESS_INVALID &&
	       it.modrm_access_type != ACCESS_NONE);
	modrm_addr = eval_modrm_addr((const void *)rip + it.bytes_prefix + it.bytes_opcode,
				     prefixes,
				     it.bytes_immediate,
				     &uc->uc_mcontext);

	printf("%lx: Access %lx %c%c\n",
	       rip,
	       modrm_addr,
	       it.modrm_access_type & ACCESS_R ? 'r' : '.',
	       it.modrm_access_type & ACCESS_W ? 'w' : '.');
}

static void
install_breakpoints(struct loaded_object *lo)
{
	/* For now, breakpoint on every memory access */
	unsigned nr_breakpoints = lo->nr_instrs;
	unsigned x;

	lo->nr_breakpoints = nr_breakpoints;
	lo->breakpoints = malloc(sizeof(lo->breakpoints[0]) * nr_breakpoints);
	for (x = 0; x < nr_breakpoints; x++)
		lo->breakpoints[x] = set_breakpoint(lo->instrs[x], memory_access_breakpoint, lo);
}

static void
loaded_object(const char *name, unsigned long addr,
	      const Elf64_Phdr *phdrs, unsigned nr_phdrs)
{
	struct loaded_object *lo;
	const char *start, *end;
	unsigned x;
	int fd;
	ssize_t s;
	const Elf64_Ehdr *hdr;
	const Elf64_Shdr *shdrs;
	unsigned nr_shdrs;
	const void *shstrtab;
	const void *current_instr;
	const void *end_instr;

	if (!addr)
		return;
	for (lo = first_loaded_object; lo; lo = lo->next) {
		if (!strcmp(name, lo->name)) {
			lo->live = 1;
			return;
		}
	}

	start = objects_to_examine;
	while (*start) {
		end = start;
		while (*end && *end != ':')
			end++;
		if (strlen(name) == end - start &&
		    !memcmp(name, start, end - start))
			goto doit;
		if (*end)
			start = end + 1;
		else
			start = end;
	}

	return;
doit:
	printf("%s %lx\n", name, addr);

	lo = calloc(sizeof(*lo), 1);
	lo->nr_instrs_alloced = 128;
	lo->instrs = malloc(lo->nr_instrs_alloced * sizeof(lo->instrs[0]));
	lo->name = strdup(name);
	lo->live = 1;
	lo->next = first_loaded_object;
	first_loaded_object = lo;

	fd = open(name, O_RDONLY);
	if (fd < 0)
		err(1, "opening %s", name);
	s = lseek(fd, 0, SEEK_END);
	if (s < 0)
		err(1, "finding size of %s", name);

	s = (s + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	hdr = mmap(NULL, s, PROT_READ, MAP_PRIVATE, fd, 0);
	if (hdr == MAP_FAILED)
		err(1, "mmap() %s", name);
	close(fd);

	if (hdr->e_ident[0] != 0x7f ||
	    hdr->e_ident[1] != 'E' ||
	    hdr->e_ident[2] != 'L' ||
	    hdr->e_ident[3] != 'F' ||
	    hdr->e_type != ET_DYN ||
	    hdr->e_shentsize != sizeof(ElfW(Shdr)))
		err(1, "%s isn't a valid ELF DSO", name);
	nr_shdrs = hdr->e_shnum;
	if (nr_shdrs == 0) {
		warnx("%s has no section headers?", name);
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
		current_instr =
			shdrs[x].sh_addr + (void *)hdr;
		end_instr = current_instr + shdrs[x].sh_size;
		while (current_instr < end_instr) {
			current_instr += handle_instruction(
				(const unsigned char *)hdr,
				current_instr,
				(void *)addr + ((void *)current_instr - (void *)hdr),
				lo);
		}
	}

	install_breakpoints(lo);

	munmap((void *)hdr, s);
}

static void
unloaded_object(struct loaded_object *lo)
{
	free(lo->name);
	free(lo);
}

static int
dip_callback(struct dl_phdr_info *dpi, size_t sz, void *ignore)
{
	loaded_object(dpi->dlpi_name, dpi->dlpi_addr,
		      dpi->dlpi_phdr, dpi->dlpi_phnum);
	return 0;
}

static void
scan_link_table(void)
{
	struct loaded_object *lo, *next, *nextnext;

	for (lo = first_loaded_object; lo; lo = lo->next)
		lo->live = 0;

	dl_iterate_phdr(dip_callback, NULL);

	lo = first_loaded_object;
	while (lo && !lo->live) {
		next = lo->next;
		unloaded_object(lo);
		lo = next;
	}
	while (lo) {
		assert(lo->live);
		next = lo->next;
		if (!next)
			break;
		if (!next->live) {
			nextnext = next->next;
			unloaded_object(next);
			lo->next = nextnext;
		} else {
			lo = next;
		}
	}
}

static void ndc_main(void) __attribute__((constructor));
static void
ndc_main()
{
	struct sigaction new_sa;
	struct sigaction old_sa;

	if (_r_debug.r_version != 1) {
		fprintf(stderr, "NDC: unexpected linker version %d (wanted 1), aborting\n",
			_r_debug.r_version);
		return;
	}

	objects_to_examine = getenv("NDC_OBJS");
	if (!objects_to_examine) {
		fprintf(stderr, "NDC_OBJS not set; aborting.\n");
		return;
	}

	memset(&old_sa, 0, sizeof(old_sa));
	new_sa.sa_sigaction = breakpoint_handler;
	sigfillset(&new_sa.sa_mask);
	new_sa.sa_flags = SA_RESTART | SA_SIGINFO;

	if (sigaction(SIGTRAP, &new_sa, &old_sa) < 0) {
		fprintf(stderr, "NDC: cannot install SIGTRAP handler, aborting\n");
		return;
	}
	if ((old_sa.sa_flags & SA_SIGINFO) || old_sa.sa_handler != SIG_DFL)
		fprintf(stderr, "NDC: client already had a SIGTRAP handler set, expect strange behaviour\n");

	if (!set_breakpoint(_r_debug.r_brk, linker_changed_break, NULL))
		err(1, "NDC setting linker changed breakpoint");

	printf("Ready to go...\n");

	scan_link_table();
}


