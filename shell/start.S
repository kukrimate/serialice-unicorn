/*
 * SerialICE
 *
 * Copyright (C) 2009 coresystems GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc.
 */

#include "serialice.h"

/* CR0 flags */
#define CR0_PE          (1 <<  0)
#define CR0_MP          (1 <<  1)
#define CR0_EM          (1 <<  2)
#define CR0_TS          (1 <<  3)
#define CR0_ET          (1 <<  4)
#define CR0_NE          (1 <<  5)
#define CR0_WP          (1 << 16)
#define CR0_AM          (1 << 18)
#define CR0_NW          (1 << 29)
#define CR0_CD          (1 << 30)
#define CR0_PG          (1 << 31)


/*  These are the region types  */
#define MTRR_TYPE_UNCACHEABLE           0
#define MTRR_TYPE_WRCOMB                1
#define MTRR_TYPE_WRTHROUGH             4
#define MTRR_TYPE_WRPROT                5
#define MTRR_TYPE_WRBACK                6
#define MTRR_NUM_TYPES                  7

#define MTRR_CAP_MSR                    0x0fe

#define MTRR_CAP_PRMRR                  (1 << 12)
#define MTRR_CAP_SMRR                   (1 << 11)
#define MTRR_CAP_WC                     (1 << 10)
#define MTRR_CAP_FIX                    (1 << 8)
#define MTRR_CAP_VCNT                   0xff

#define MTRR_DEF_TYPE_MSR               0x2ff
#define MTRR_DEF_TYPE_MASK              0xff
#define MTRR_DEF_TYPE_EN                (1 << 11)
#define MTRR_DEF_TYPE_FIX_EN            (1 << 10)

#define IA32_SMRR_PHYS_BASE             0x1f2
#define IA32_SMRR_PHYS_MASK             0x1f3
#define SMRR_PHYS_MASK_LOCK             (1 << 10)

/* Specific to model_6fx and model_1067x.
   These are named MSR_SMRR_PHYSBASE in the SDM. */
#define CORE2_SMRR_PHYS_BASE            0xa0
#define CORE2_SMRR_PHYS_MASK            0xa1

#define MTRR_PHYS_BASE(reg)             (0x200 + 2 * (reg))
#define MTRR_PHYS_MASK(reg)             (MTRR_PHYS_BASE(reg) + 1)
#define  MTRR_PHYS_MASK_VALID           (1 << 11)

#define NUM_FIXED_RANGES                88
#define RANGES_PER_FIXED_MTRR           8
#define NUM_FIXED_MTRRS                 (NUM_FIXED_RANGES / RANGES_PER_FIXED_MTRR)
#define MTRR_FIX_64K_00000              0x250
#define MTRR_FIX_16K_80000              0x258
#define MTRR_FIX_16K_A0000              0x259
#define MTRR_FIX_4K_C0000               0x268
#define MTRR_FIX_4K_C8000               0x269
#define MTRR_FIX_4K_D0000               0x26a
#define MTRR_FIX_4K_D8000               0x26b
#define MTRR_FIX_4K_E0000               0x26c
#define MTRR_FIX_4K_E8000               0x26d
#define MTRR_FIX_4K_F0000               0x26e
#define MTRR_FIX_4K_F8000               0x26f


/*
 * macro: find_free_mtrr
 * Clobbers: %eax, %ebx, %ecx, %edx.
 * Returns:
 * %ebx contains the number of freely available MTRR's.
 *      It should be checked against 0.
 * %ecx holds the MTRR_BASE of the free MTRR.
 */
.macro find_free_mtrr
	/* Figure out how many MTRRs we have */
	mov	$MTRR_CAP_MSR, %ecx
	rdmsr
	movzb	%al, %ebx		/* Number of variable MTRRs */

	/* Find a free variable MTRR */
	movl	$MTRR_PHYS_MASK(0), %ecx
1:
	rdmsr
	test	$MTRR_PHYS_MASK_VALID, %eax
	jz	2f
	addl	$2, %ecx
	dec	%ebx
	jnz	1b
2:
	/* %ecx needs to hold the MTRR_BASE */
	decl	%ecx
.endm

	.section ".start", "a"
	.code32

fixed_mtrr_list:
	.word	MTRR_FIX_64K_00000
	.word	MTRR_FIX_16K_80000
	.word	MTRR_FIX_16K_A0000
	.word	MTRR_FIX_4K_C0000
	.word	MTRR_FIX_4K_C8000
	.word	MTRR_FIX_4K_D0000
	.word	MTRR_FIX_4K_D8000
	.word	MTRR_FIX_4K_E0000
	.word	MTRR_FIX_4K_E8000
	.word	MTRR_FIX_4K_F0000
	.word	MTRR_FIX_4K_F8000
fixed_mtrr_list_end:

check_mtrr:
        /* Use the MTRR default type MSR as a proxy for detecting INIT#.
         * Reset the system if any known bits are set in that MSR. That is
         * an indication of the CPU not being properly reset. */

check_for_clean_reset:
        movl    $MTRR_DEF_TYPE_MSR, %ecx
        rdmsr
        andl    $(MTRR_DEF_TYPE_EN | MTRR_DEF_TYPE_FIX_EN), %eax
        cmp     $0, %eax
        jnz     warm_reset
        jmp     *%esp
        /* perform warm reset */
warm_reset:
        movw    $0xcf9, %dx
        movb    $0x06, %al
        outb    %al, %dx
        /* Should not reach this*/
1:
        hlt
        jmp     1b

.halt_forever:
	hlt
	jmp	.halt_forever

_c_main:
	movl	%eax, %ebp

	/* Enable FPU registers */
	movl	%cr0, %eax
	andl	$~(1 << 2), %eax
	movl	%eax, %cr0

#ifdef CONFIG_HAVE_SSE
	/* enable SSE */
	movl	%cr4, %eax
	orl	$(3<<9), %eax
	movl	%eax, %cr4
#endif

	movl	%ebp, %eax

	/* MTRR setup */

	movl	$no_reset, %esp /* return address */
	jmp	check_mtrr /* Check if CPU properly reset */

no_reset:

	/* Clear/disable fixed MTRRs */
	mov	$fixed_mtrr_list, %ebx
	xor	%eax, %eax
	xor	%edx, %edx

clear_fixed_mtrr:
	movzwl	(%ebx), %ecx
	wrmsr
	add	$2, %ebx
	cmp	$fixed_mtrr_list_end, %ebx
	jl	clear_fixed_mtrr

	/* Figure out how many MTRRs we have, and clear them out */
	mov	$MTRR_CAP_MSR, %ecx
	rdmsr
	movzb	%al, %ebx		/* Number of variable MTRRs */
	mov	$MTRR_PHYS_BASE(0), %ecx
	xor	%eax, %eax
	xor	%edx, %edx

clear_var_mtrr:
	wrmsr
	inc	%ecx
	wrmsr
	inc	%ecx
	dec	%ebx
	jnz	clear_var_mtrr

	/* Configure default memory type to uncacheable (UC) */
	mov	$MTRR_DEF_TYPE_MSR, %ecx
	rdmsr
	/* Clear enable bits and set default type to UC. */
	and	$~(MTRR_DEF_TYPE_MASK | MTRR_DEF_TYPE_EN | \
		 MTRR_DEF_TYPE_FIX_EN), %eax
	wrmsr

	/* Setup XIP ROM to WP cachable */
	find_free_mtrr
	test	%ebx, %ebx
	jz	.halt_forever

	mov	$0xff000000, %eax
	or	$MTRR_TYPE_WRPROT, %eax
	xor	%edx,%edx
	wrmsr

	inc	%ecx
	mov	$0x1000000, %eax
	dec	%eax
	not	%eax
	or	$MTRR_PHYS_MASK_VALID, %eax
	movl	%esi, %edx
	wrmsr

	/* Enable variable MTRRs */
	mov	$MTRR_DEF_TYPE_MSR, %ecx
	rdmsr
	or	$MTRR_DEF_TYPE_EN, %eax
	wrmsr

	/* Enable caching */
	mov	%cr0, %eax
	and	$~(CR0_CD | CR0_NW), %eax
	invd
	mov	%eax, %cr0

	/* Setting up the stack (xmmstack only?) */
	xorl	%esp,%esp
	movl	$0x7f,%esp #Start address of XMM/MMX stack.
	movl	%esp,%dr2  #DR2 contains stack(low byte) and offset(hi byte)

	jmp	main

_pmode_start:
	/* Set up protected mode registers */
	lgdt	%cs:gdt
	ljmp	$0x08, $1f
1:
	movl	%eax, %ebp
	movw	$0x10, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	movw	%ax, %fs
	movw	%ax, %gs

	movl	%ebp, %eax

	jmp	_c_main

	.code16
_start:
	/* Go to protected mode */
	cli
	movl	%eax, %ebp
	xorl	%eax, %eax
	movl	%eax, %cr3
	movw	%cs, %ax
	shlw	$4, %ax
	movw	$gdt, %bx
	subw	%ax, %bx
	data32	lgdt %cs:(%bx)

	movl	%cr0, %eax
	andl	$0x7ffaffd1, %eax
	orl	$0x60000001, %eax
	movl	%eax, %cr0

	movl	%ebp, %eax
	data32	ljmp $0x08, $_pmode_start


	/* GDT */
	.align 4
gdt:
	.word	gdt_size
	.long	gdt
	.word	0

	.word	0xffff, 0x0000
	.byte	0x00, 0x9b, 0xcf, 0x00

	.word	0xffff, 0x0000
	.byte	0x00, 0x93, 0xcf, 0x00
gdt_size = (. - gdt - 1)

	/* Messages */
	.section ".messages", "a", @progbits
	.globl	program_name
program_name:
	.ascii "SerialICE v" VERSION " (" __DATE__ ")"
	.byte 0x00
	.globl program_copyright
program_copyright:
	.string "Copyright (C) 2009 coresystems GmbH."

	/* Reset Vector */
	.section ".reset", "a"
	.globl	reset_vector
reset_vector:
	.code16
	jmp _start

	/* VIA romstrap */
	.section ".romstrap", "a", @progbits
#ifdef CONFIG_VIA_ROMSTRAP
/* The pointer to above table should be at 0xffffd,
 * the table itself MUST be aligned to 128B it seems!
 */
	.long via_romstrap
#endif

#ifdef CONFIG_CK804_ROMSTRAP
/* Pointers to nvidia tables at 0xffffe0 */
	. = 0x10;
	.long ck804_romstrap
	.long ck804_romstrap
	.long ck804_romstrap
	.long ck804_romstrap
#endif

#ifdef CONFIG_MCP55_ROMSTRAP
/* Pointers to nvidia tables at 0xffffe0 */
	. = 0x10;
	.long mcp55_romstrap
	.long mcp55_romstrap
	.long mcp55_romstrap
	.long mcp55_romstrap
#endif
