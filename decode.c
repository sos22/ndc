/* Instruction decoding gubbins */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <assert.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ndc.h"

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

static unsigned
instr_size(const struct instr_template *it)
{
	return it->bytes_prefix + it->bytes_opcode + it->bytes_modrm + it->bytes_immediate;
}

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
		add_mem_access_instr(lo, mapped_at, it->modrm_access_type);
}

void
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
		case 0x51 ... 0x6f:
		case 0x74 ... 0x76:
		case 0xd0 ... 0xd5:
		case 0xd8 ... 0xdf:
		case 0xe8 ... 0xef:
		case 0xf8 ... 0xff:

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

		case 0x71 ... 0x73: /* group 12 through 14 N,Ib or U, Ib */
			it->bytes_immediate = 1;
			it->modrm_access_type = ACCESS_NONE;
			break;

		case 0x7e: /* Movd with mode one of Ed/q, Pd/q; Vq, Wq; Ed/q, Vd/q */
			if (*prefixes & (1 << PFX_REP))
				it->modrm_access_type = ACCESS_R;
			else
				it->modrm_access_type = ACCESS_W;
			break;

		case 0x11:
		case 0x7f:
		case 0x90 ... 0x9f: /* setcc */
		case 0xe7: /* movnt M, V */
			it->modrm_access_type = ACCESS_W;
			break;

		case 0xc1: /* xadd Ev, Gv */
			it->modrm_access_type = ACCESS_RW;
			break;

		case 0xc2:
			it->modrm_access_type = ACCESS_R;
			it->bytes_immediate = 1;
			break;

		case 0x77: /* emms */
		case 0xc8 ... 0xcf: /* bswap reg */
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

unsigned long
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

struct loaded_object *
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
		return lo;
	}

	msg(15, "Processing %s at %lx\n", fname, start_vaddr - offset);
	lo = calloc(sizeof(*lo), 1);
	lo->name = strdup(fname);
	lo->nr_instrs_alloced = 128;
	lo->nr_instrs = 0;
	lo->next_instr_to_set_bp_on = random();
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
		return NULL;
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

	munmap((void *)hdr, s);

	msg(10, "Done %s\n", fname);

	return lo;
}

