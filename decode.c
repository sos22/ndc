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

static unsigned
instr_size(const struct instr_template *it)
{
	return it->bytes_prefix + it->bytes_opcode + it->bytes_modrm + it->bytes_immediate;
}

/* Assume that we're executing an instruction and the registers in the
   mask @stack_registers_on_entry currently contain pointers into the
   stack.  Does the modrm of this instruction point at the stack?
   Returns true if it definitely does, or false if it might not. */
static bool
modrm_points_at_stack(const unsigned char *text,
		      const struct instr_template *it,
		      unsigned long stack_registers_on_entry)
{
	/* This moderately messy */
	unsigned char modrm = text[it->bytes_prefix + it->bytes_opcode];
	unsigned char mod = modrm >> 6;
	unsigned char rm = modrm & 7;
	bool is_stack;
	unsigned modrm_mrm_reg;

	assert(mod != 3);

	modrm_mrm_reg = modrm & 7;
	if (it->prefixes & (1 << PFX_REX_R))
		modrm_mrm_reg |= 8;

	if (rm == 4) {
		unsigned char sib = text[it->bytes_prefix + it->bytes_opcode + 1];
		unsigned base = sib & 7;
		unsigned index = (sib >> 3) & 7;
		unsigned scale = sib >> 6;

		if (mod == 0 && base == 5) {
			is_stack = false;
		} else {
			if (it->prefixes & (1 << PFX_REX_B))
				base |= 8;
			is_stack = !!(stack_registers_on_entry & (1 << base));
		}
		if (it->prefixes & (1 << PFX_REX_X))
			index |= 8;
		if (!is_stack && scale == 0 && (index != 4)) {
			is_stack = !!(stack_registers_on_entry & (1 << index));
		}
	} else if (mod == 0 && rm == 5) {
		is_stack = false;
	} else {
		is_stack = !!(stack_registers_on_entry & (1 << modrm_mrm_reg));
	}
	return is_stack;
}

static void
modrm(const unsigned char *instr,
      struct instr_template *it,
      unsigned long mapped_at,
      struct loaded_object *lo,
      unsigned long stack_registers_on_entry)
{
	unsigned char modrm = instr[it->bytes_prefix + it->bytes_opcode];
	unsigned mod = modrm >> 6;
	int interesting = it->modrm_access_type != ACCESS_NONE;

	if (mod == 3) {
		/* Register -> not interesting */
		interesting = 0;
	} else if (modrm_points_at_stack(instr, it, stack_registers_on_entry)) {
		interesting = 0;
	}

	if (interesting)
		add_mem_access_instr(lo, mapped_at, it->modrm_access_type);
}

void
find_instr_template(const unsigned char *instr,
		    unsigned long addr,
		    struct instr_template *it)
{
	unsigned opcode;
	unsigned imm_opsize;

	memset(it, 0, sizeof(*it));

	it->modrm_access_type = ACCESS_INVALID;

	while (1) {
		it->bytes_prefix++;
		switch (instr[it->bytes_prefix-1]) {
		case 0x26:
			it->prefixes |= 1 << PFX_ES;
			break;
		case 0x2e:
			it->prefixes |= 1 << PFX_CS;
			break;
		case 0x36:
			it->prefixes |= 1 << PFX_SS;
			break;
		case 0x3e:
			it->prefixes |= 1 << PFX_DS;
			break;
		case 0x64:
			it->prefixes |= 1 << PFX_FS;
			break;
		case 0x65:
			it->prefixes |= 1 << PFX_GS;
			break;
		case 0x66:
			it->prefixes |= 1 << PFX_OPSIZE;
			break;
		case 0x67:
			it->prefixes |= 1 << PFX_ADDRSIZE;
			break;
		case 0xF0:
			it->prefixes |= 1 << PFX_LOCK;
			break;
		case 0xF2:
			it->prefixes |= 1 << PFX_REPN;
			break;
		case 0xF3:
			it->prefixes |= 1 << PFX_REP;
			break;
		default:
			goto done_prefixes;
		}
	}
done_prefixes:
	it->bytes_prefix--;

	if (instr[it->bytes_prefix] >= 0x40 && instr[it->bytes_prefix] <= 0x4f) {
		it->prefixes |= 1 << PFX_REX_0;
		if (instr[it->bytes_prefix] & 1)
			it->prefixes |= 1 << PFX_REX_B;
		if (instr[it->bytes_prefix] & 2)
			it->prefixes |= 1 << PFX_REX_X;
		if (instr[it->bytes_prefix] & 4)
			it->prefixes |= 1 << PFX_REX_R;
		if (instr[it->bytes_prefix] & 8)
			it->prefixes |= 1 << PFX_REX_W;
		it->bytes_prefix++;
	}

	imm_opsize = 4;
	if (it->prefixes & (1 << PFX_OPSIZE))
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
		case 0x18: /* prefetch */
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
		case 0xa3: /* bt Ev, Gv */
		case 0xaf: /* imul Gv, Ev */
		case 0xb6: /* movz Gv, Eb */
		case 0xb7: /* movz Gv, Ew */
		case 0xbd: /* bsr Gv, Ev */
		case 0xbe: /* movsz Gb, Eb */
		case 0xbf: /* movsz Gb, Ew */
			it->modrm_access_type = ACCESS_R;
			break;

		case 0xd6:
			if (it->prefixes & (1 << PFX_OPSIZE))
				it->modrm_access_type = ACCESS_W;
			else
				it->modrm_access_type = ACCESS_R;
			break;

		case 0x71 ... 0x73: /* group 12 through 14 N,Ib or U, Ib */
			it->bytes_immediate = 1;
			it->modrm_access_type = ACCESS_NONE;
			break;

		case 0x7e: /* Movd with mode one of Ed/q, Pd/q; Vq, Wq; Ed/q, Vd/q */
			if (it->prefixes & (1 << PFX_REP))
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
		case 0xb1: /* cmpxchg Ev, Gv */
			it->modrm_access_type = ACCESS_RW;
			break;

		case 0xc2:
			it->modrm_access_type = ACCESS_R;
			it->bytes_immediate = 1;
			break;

		case 0x31: /* rdtsc */
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
	case 0x87: /* xchg Ev, Gv */
	case 0x86: /* xchg Eb, Gb */
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

	case 0x6b: /* imul Gv, Ev, Ib */
		it->modrm_access_type = ACCESS_R;
		it->bytes_immediate = 1;
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
	case 0x99: /* cltd */
	case 0xc3: /* ret */
	case 0xc9: /* leave */
	case 0xf4: /* hlt */

	case 0xa6: /* cmps.  This does access memory, but it's in a
		      moderately hard-to-handle way, so just ignore
		      it. */
	case 0xaa: /* stosb */
	case 0xab: /* stos */
	case 0xa4: /* movs */
	case 0xa5: /* movsb */
	case 0xae: /* scas */
		break;

	case 0x3d: /* cmp rax, Iz */
	case 0x68: /* push Iz */
	case 0xa9: /* test rax, Iz */
	case 0xe8: /* Call Jz */
	case 0xe9: /* jmp Jz */
		it->bytes_immediate = imm_opsize;
		break;

	case 0xb8 ... 0xbf: /* mov reg, Iz */
		if (it->prefixes & (1 << PFX_REX_W))
			it->bytes_immediate = 8;
		else if (it->prefixes & (1 << PFX_OPSIZE))
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

		if (it->prefixes & (1 << PFX_REX_B))
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
		if (it->prefixes & (1 << PFX_REX_X))
			index |= 8;
		if (index != 4)
			sibval += fetch_reg_by_index(urs, index) * scale;

		return sibval;
	}

	disp_bytes = modrm_bytes + 1;

	reg = fetch_reg_by_index(
		urs,
		rm | (it->prefixes & (1 << PFX_REX_B) ? 8 : 0));

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
discover_function(struct loaded_object *lo,
		  const char *name,
		  unsigned long addr)
{
	struct function *f;
	list_foreach(&lo->functions, f, list) {
		if (f->head == addr)
			return;
	}
	f = calloc(sizeof(*f), 1);
	if (name)
		f->name = strdup(name);
	f->head = addr;
	list_push(f, list, &lo->functions);
}

static unsigned long
instr_opcode(const struct instruction *i)
{
	if (i->template.bytes_opcode == 1)
		return i->text[i->template.bytes_prefix];
	else if (i->template.bytes_opcode == 2)
		return ((unsigned long)i->text[i->template.bytes_prefix] << 8) |
			i->text[i->template.bytes_prefix+1];
	else
		abort();
}

struct address_queue {
	unsigned nr_queued;
	unsigned nr_alloced;
	unsigned long *content;
};

static unsigned long
queue_pop(struct address_queue *q)
{
	unsigned long a;
	a = q->content[q->nr_queued-1];
	q->nr_queued--;
	return a;
}

static void
queue_push(struct address_queue *q, unsigned long a)
{
	if (q->nr_queued == q->nr_alloced) {
		q->nr_alloced += 32;
		q->content = realloc(q->content, sizeof(q->content[0]) * q->nr_alloced);
	}
	q->content[q->nr_queued] = a;
	q->nr_queued++;
}

static bool
queue_empty(const struct address_queue *q)
{
	return q->nr_queued == 0;
}

static bool
addr_known(const struct partial_cfg *pc, unsigned long addr)
{
	const struct instruction *i;
	list_foreach(&pc->instructions, i, list)
		if (i->addr == addr)
			return true;
	return false;
}

static struct instruction *
find_instruction(struct partial_cfg *pc, unsigned long addr)
{
	struct instruction *i;
	list_foreach(&pc->instructions, i, list)
		if (i->addr == addr)
			return i;
	abort();
}

/* Assume that stack_registers_on_entry is set corerctly, and figure
   out which registers will point at the stack after this
   instruction. */
static unsigned long
compute_stack_registers_on_exit(struct instruction *i)
{
	unsigned long res = i->stack_registers_on_entry;
	unsigned modrm_reg;
	unsigned modrm_mrm_reg;
	bool have_modrm_mrm_reg;

	have_modrm_mrm_reg = false;
	if (i->template.modrm_access_type != ACCESS_INVALID) {
		unsigned char modrm = i->text[i->template.bytes_prefix + i->template.bytes_opcode];
		modrm_reg = (modrm >> 3) & 7;
		if (i->template.prefixes & (1 << PFX_REX_R))
			modrm_reg |= 8;
		if ((modrm >> 6) == 3) {
			modrm_mrm_reg = modrm & 7;
			if (i->template.prefixes & (1 << PFX_REX_R))
				modrm_mrm_reg |= 8;
			have_modrm_mrm_reg = true;
		}
	}

	switch (instr_opcode(i)) {
		/* Things which propagate stackness from one register
		   to another */
	case 1: /* add Ev, Gv */
	case 0x29: /* sub Ev, Gv */
		if (have_modrm_mrm_reg) {
			if (res & (1 << modrm_reg))
				res |= 1 << modrm_mrm_reg;
		}
		break;

	case 3: /* add Gv, Ev */
	case 0x2b: /* sub Gv, Ev */
	case 0x8b: /* mov Gv, Ev */
		res &= ~(1 << modrm_reg);
		if (have_modrm_mrm_reg &&
		    (res & (1 << modrm_mrm_reg)))
			res |= 1 << modrm_reg;
		break;

	case 0x89: /* mov Ev, Gv */
		if (have_modrm_mrm_reg) {
			if (res & (1 << modrm_reg))
				res |= 1 << modrm_mrm_reg;
			else
				res &= ~(1 << modrm_mrm_reg);
		}
		break;

	case 0x8d: { /* lea Gv, M */
		bool is_stack = modrm_points_at_stack(i->text, &i->template, i->stack_registers_on_entry);
		if (is_stack)
			res |= 1 << modrm_reg;
		else
			res &= ~(1 << modrm_reg);
		break;
	}

		/* Now for instructions which unconditionally
		 * un-stackify their target */

	case 0x0fc0: /* xadd */
	case 0x0fc1:
		res &= ~(1 << modrm_reg);
		if (have_modrm_mrm_reg)
			res &= ~(1 << modrm_mrm_reg);
		break;

	case 0x0fa2: /* cpuid */
		res &= ~0xf;
		break;

	case 0x90 ... 0x9f: { /* xchg reg, rax */
		unsigned r = instr_opcode(i) & 7;
		res &= ~1;
		if (i->template.prefixes & (1 << PFX_REX_B))
			r |= 8;
		res &= ~(1 << r);
		break;
	}

		/* cmpxchg */
	case 0x0fb0:
	case 0x0fb1:
		res &= ~1;
		if (have_modrm_mrm_reg)
			res &= ~(1 << modrm_mrm_reg);
		break;

		/* syscalls */
	case 0xcd: case 0x0f05:
		res = 1 << 4;
		break;

		/* Target is E-type */
	case 0x00: case 0x08: case 0x09: case 0x10: case 0x11:
	case 0x18: case 0x19: case 0x20: case 0x21: case 0x28:
	case 0x30: case 0x31: case 0x68:
	case 0x80 ... 0x83: case 0x88:
	case 0xc0: case 0xc1: case 0xc6: case 0xc7:
	case 0xd0 ... 0xd3: case 0xf6: case 0xf7:
	case 0x0f90 ... 0x0f9f: case 0x0fa4 ... 0x0fa5:
	case 0x0fb3: case 0x0f7e: case 0x0fab ... 0x0fad:
	case 0x0fbb: case 0x0fba: case 0x0fc6: case 0x0fc7:
		if (have_modrm_mrm_reg)
			res &= ~(1 << modrm_mrm_reg);
		break;

		/* Target G-type */
	case 0x02: case 0x0a: case 0x0b: case 0x12: case 0x13: case 0x1a:
	case 0x1b: case 0x22: case 0x23: case 0x2a:
	case 0x32: case 0x33: case 0x69: case 0x6b:
	case 0x8a: case 0x0f02: case 0x0f03: case 0x0f40 ... 0x0f4f:
	case 0x0f50: case 0x0fb2: case 0x0fb4 ... 0x0fb7:
	case 0x0fc5: case 0x0fd7: case 0x0faf: case 0x0fbc ... 0x0fbf:
		res &= ~(1 << modrm_reg);
		break;

		/* Target both G and E type */
	case 0x86: case 0x87:
		res &= ~(1 << modrm_reg);
		if (have_modrm_mrm_reg)
			res &= ~(1 << modrm_mrm_reg);
		break;

		/* Target encoded in opcode */
	case 0x58 ... 0x5f:
	case 0xb0 ... 0xb7:
	case 0xb8 ... 0xbf:
	case 0x0fc8 ... 0x0fcf: {
		unsigned r = instr_opcode(i) & 7;
		if (i->template.prefixes & (1 << PFX_REX_B))
			r |= 8;
		res &= ~(1 << r);
		break;
	}

		/* Target rcx */
	case 0xa4 ... 0xa7: case 0xaa ... 0xaf:
		res &= ~2;
		break;

		/* target rax */
	case 0xa0 ... 0xa3: case 0xe4: case 0xe5:
	case 0xec: case 0xed:
		res &= ~1;
		break;

	default:
		/* Anything else leaves the state alone */
		break;
	}

	/* RSP always points at the stack */
	res |= 1ul << 4;

	return res;
}

static struct partial_cfg *
build_cfg_from(struct loaded_object *lo, unsigned long addr, unsigned long map_delta)
{
	struct partial_cfg *work;
	struct address_queue queue = {0};
	struct instruction *i;
	unsigned long branch_target;
	void *immediate;
	unsigned long head = addr;
	bool converged;

	work = calloc(sizeof(*work), 1);
	init_list_head(&work->instructions);

	printf("Investigating function at %lx...\n", addr);

	/* First, discover all of the possibly-relevant instructions */
	queue_push(&queue, addr);
	while (!queue_empty(&queue)) {
		addr = queue_pop(&queue);
		if (addr_known(work, addr))
			continue;
		i = calloc(sizeof(*i), 1);
		list_push(i, list, &work->instructions);
		i->addr = addr;
		find_instr_template( (const void *)(addr + map_delta),
				     addr,
				     &i->template);
		memcpy(i->text, (const void *)(addr + map_delta),
		       instr_size(&i->template));

		i->next.a = addr + instr_size(&i->template);
		branch_target = i->next.a;
		immediate = i->text + i->template.bytes_prefix + i->template.bytes_opcode + i->template.bytes_modrm;
		if (i->template.bytes_immediate == 1)
			branch_target += *(char *)immediate;
		else if (i->template.bytes_immediate == 2)
			branch_target += *(short *)immediate;
		else if (i->template.bytes_immediate == 4)
			branch_target += *(int *)immediate;
		else if (i->template.bytes_immediate == 8)
			branch_target += *(long *)immediate;
		else {
			assert(i->template.bytes_immediate == 0);
		}

		switch (instr_opcode(i)) {
			/* 2-exit instructions where the delta is
			   encoded as an immediate value. */
		case 0x70 ... 0x7f: /* jcc */
		case 0x0f80 ... 0x0f8f: /* jcc */
		case 0xe0: case 0xe1: /* loopcc */
		case 0xe3: /* jcxz */
			i->branch.a = branch_target;
			break;

			/* 0-exit instructions */
		case 0xc2: case 0xc3: /* ret near */
		case 0xca: case 0xcb: /* ret far */
		case 0xcc: /* int3 */
		case 0xcf: /* iret */
		case 0xf1: /* int1 */
		case 0xf4: /* hlt */
		case 0x0f0b: /* ud2 */
			i->next.a = 0;
			break;

			/* 1-exit instructions which don't fall
			   through.  Target is assumed to be encoded
			   as an immediate value. */
		case 0xe2: /* loop */
		case 0xe9: /* Jmp Jz */
		case 0xeb: /* Jmp Jb */
			i->next.a = 0;
			i->branch.a = branch_target;
			break;

		case 0xff: { /* Group 5 */
			unsigned char modrm = i->text[i->template.bytes_prefix + i->template.bytes_opcode];
			unsigned reg = (modrm >> 3) & 7;
			switch (reg) {
			case 0: /* inc */
			case 1: /* dec */
			case 2: /* Call Ev, treat as normal instruction */
			case 3: /* Call Mp, treat as normal instruction */
				break;
			case 4: /* jmp Ev, treat as 0-exit */
			case 5: /* jmp Mp, treat as 0-exit */
				i->next.a = 0;
				break;
			case 6: /* push ev */
				break;
			case 7: /* Reserved */
				abort();
			}
			break;
		}

		case 0xe8: /* call.  Treated as a normal instruction,
			      except that we discover a new entry
			      point. */
			discover_function(lo, NULL, branch_target);
			break;

			/* Other abnormal-exit instructions.  We
			   pretty much just pretend that these are
			   normal at this stage. */
		case 0x0f05: /* syscall */
		case 0xcd: /* int n */
			break;

			/* Normal single-exit instructions */
		default:
			break;
		}

		if (i->next.a)
			queue_push(&queue, i->next.a);
		if (i->branch.a)
			queue_push(&queue, i->branch.a);
	}

	/* Now go and resolve all of those branches into appropriate
	 * instruction structures */
	list_foreach(&work->instructions, i, list) {
		if (i->next.a)
			i->next.i = find_instruction(work, i->next.a);
		if (i->branch.a)
			i->branch.i = find_instruction(work, i->branch.a);
	}
	work->head = find_instruction(work, head);

	/* Now try to figure out which instructions are accessing the
	   stack.  Those which actually use rsp are easy, but we also
	   try to determine whether something is using the stack
	   through some other register using a bit of static
	   analysis. */
	/* Aim here is to build, for each instruction, a set of
	   registers which are definitely pointing at the stack at
	   that instruction.  We start off assuming that every
	   register always points at the stack, then mark the head so
	   that only RSP is a stack pointer, and then fix up all the
	   contradictions, iterating to a fixed point. */
	list_foreach(&work->instructions, i, list) {
		i->stack_registers_on_entry = ~0ul;
	}
	work->head->stack_registers_on_entry = 1ul << 4; /* Register 4 is
							  * RSP in x86
							  * encoding */

	converged = false;
	while (!converged) {
		converged = true;
		list_foreach(&work->instructions, i, list) {
			unsigned long desired_mask =
				compute_stack_registers_on_exit(i);
			if (i->next.i &&
			    (i->next.i->stack_registers_on_entry & ~desired_mask)) {
				i->next.i->stack_registers_on_entry &=
					desired_mask;
				converged = false;
			}
			if (i->branch.i &&
			    (i->branch.i->stack_registers_on_entry & ~desired_mask)) {
				i->branch.i->stack_registers_on_entry &=
					desired_mask;
				converged = false;
			}
		}
	}

	/* Now, finally, walk the instruction list and decide whether
	   they're candidates for breakpoints */
	list_foreach(&work->instructions, i, list) {
		if (i->template.modrm_access_type != ACCESS_INVALID)
			modrm(i->text,
			      &i->template,
			      i->addr,
			      lo,
			      i->stack_registers_on_entry);
	}

	return work;
}

static void
explore_function(struct loaded_object *lo, struct function *f,
		 unsigned long map_delta)
{
	struct partial_cfg *cfg = build_cfg_from(lo, f->head, map_delta);
	struct instruction *i;

	/* Only did that for the side effects... */
	while (!list_empty(&cfg->instructions)) {
		i = list_pop(struct instruction, list, &cfg->instructions);
		free(i);
	}
	free(cfg);
}

static void
explore_functions(struct loaded_object *lo, unsigned long map_delta)
{
	struct function *f;
	list_foreach(&lo->functions, f, list)
		explore_function(lo, f, map_delta);
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
	unsigned x;

	list_foreach(&p->loaded_objects, lo, list) {
		if (!strcmp(lo->name, fname)) {
			lo->live = true;
			return lo;
		}
	}

	msg(15, "Processing %s at %lx\n", fname, start_vaddr - offset);
	lo = calloc(sizeof(*lo), 1);
	init_list_head(&lo->breakpoints);
	init_list_head(&lo->functions);
	lo->name = strdup(fname);
	lo->nr_instrs_alloced = 128;
	lo->nr_instrs = 0;
	lo->next_instr_to_set_bp_on = random();
	lo->instrs = calloc(sizeof(lo->instrs[0]), lo->nr_instrs_alloced);
	lo->live = true;
	list_push(lo, list, &p->loaded_objects);

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

	/* First, parse up the symbol tables to find functions */
	for (x = 0; x < nr_shdrs; x++) {
		const Elf64_Shdr *str_shdr;
		const Elf64_Sym *symbols;
		const void *symstrtab;
		unsigned idx;

		if (shdrs[x].sh_type != SHT_SYMTAB &&
		    shdrs[x].sh_type != SHT_DYNSYM)
			continue;
		str_shdr = NULL;
		if (shdrs[x].sh_link != 0 && shdrs[x].sh_link < nr_shdrs)
			str_shdr = &shdrs[shdrs[x].sh_link];
		symbols = (const Elf64_Sym *)
			((unsigned long)hdr +
			 shdrs[x].sh_offset);
		symstrtab = (const void *)hdr + str_shdr->sh_offset;
		for (idx = 0;
		     idx < shdrs[x].sh_size / sizeof(symbols[0]);
		     idx++) {
			if (ELF64_ST_TYPE(symbols[idx].st_info) != STT_FUNC)
				continue;
			if (symbols[idx].st_shndx == 0 ||
			    symbols[idx].st_shndx > nr_shdrs)
				continue;
			discover_function(lo,
					  symstrtab + symbols[idx].st_name,
					  symbols[idx].st_value);
		}
	}

	/* Make sure that we explore the main entry point */
	discover_function(lo, "<entrypoint>", hdr->e_entry);

	explore_functions(lo, (unsigned long)hdr - start_vaddr);

	munmap((void *)hdr, s);

	msg(10, "Done %s\n", fname);

	return lo;
}

