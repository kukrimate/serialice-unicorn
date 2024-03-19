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

#include <types.h>
#include <serialice.h>
#include <io.h>

/* Hardware specific functions */

#include "chipset.c"

/* Serial functions */
#include "serial.c"

/* Accessor functions */

static void serialice_read_memory(void)
{
	u8 width;
	u32 addr;

	// Format:
	// *rm00000000.w
	addr = serial_get32();
	serial_getc();	// skip .
	width = serial_getc();

	serial_putc('\r'); serial_putc('\n');

	switch (width) {
	case 'b': serial_put8(read8(addr)); break;
	case 'w': serial_put16(read16(addr)); break;
	case 'l': serial_put32(read32(addr)); break;
#ifdef CONFIG_SUPPORT_64_BIT_ACCESS
	case 'q': serial_put64(read64(addr)); break;
#endif
	}
}

static void serialice_write_memory(void)
{
	u8 width;
	u32 addr;
	u32 data;
#ifdef CONFIG_SUPPORT_64_BIT_ACCESS
	u64_t data64;
#endif

	// Format:
	// *wm00000000.w=0000
	addr = serial_get32();
	serial_getc();	// skip .
	width = serial_getc();
	serial_getc();	// skip =

	switch (width) {
	case 'b': data = serial_get8(); write8(addr, (u8)data); break;
	case 'w': data = serial_get16(); write16(addr, (u16)data); break;
	case 'l': data = serial_get32(); write32(addr, (u32)data); break;
#ifdef CONFIG_SUPPORT_64_BIT_ACCESS
	case 'q': data64 = serial_get64(); write64(addr, data64); break;
#endif
	}
}

static void serialice_read_io(void)
{
	u8 width;
	u16 port;

	// Format:
	// *ri0000.w
	port = serial_get16();
	serial_getc();	// skip .
	width = serial_getc();

	serial_putc('\r'); serial_putc('\n');

	switch (width) {
	case 'b': serial_put8(inb(port)); break;
	case 'w': serial_put16(inw(port)); break;
	case 'l': serial_put32(inl(port)); break;
	}
}

static void serialice_write_io(void)
{
	u8 width;
	u16 port;
	u32 data;

	// Format:
	// *wi0000.w=0000
	port = serial_get16();
	serial_getc();	// skip .
	width = serial_getc();
	serial_getc();	// skip =

	switch (width) {
	case 'b': data = serial_get8(); outb((u8)data, port); break;
	case 'w': data = serial_get16(); outw((u16)data, port); break;
	case 'l': data = serial_get32(); outl((u32)data, port); break;
	}
}

static void serialice_read_msr(void)
{
	u32 addr, key;
	msr_t msr;

	// Format:
	// *rc00000000.9c5a203a
	addr = serial_get32();
	serial_getc();	   // skip .
	key = serial_get32(); // key in %edi

	serial_putc('\r'); serial_putc('\n');

	msr = rdmsr(addr, key);
	serial_put32(msr.hi);
	serial_putc('.');
	serial_put32(msr.lo);
}

static void serialice_write_msr(void)
{
	u32 addr, key;
	msr_t msr;

	// Format:
	// *wc00000000.9c5a203a=00000000.00000000
	addr = serial_get32();
	serial_getc();	// skip .
	key = serial_get32(); // read key in %edi
	serial_getc();	// skip =
	msr.hi = serial_get32();
	serial_getc();	// skip .
	msr.lo = serial_get32();

#ifdef __ROMCC__
	/* Cheat to avoid register outage */
	wrmsr(addr, msr, 0x9c5a203a);
#else
	wrmsr(addr, msr, key);
#endif
}

static void serialice_cpuinfo(void)
{
	u32 eax, ecx;
	u32 reg32;

	// Format:
	//    --EAX--- --ECX---
	// *ci00000000.00000000
	eax = serial_get32();
	serial_getc(); // skip .
	ecx = serial_get32();

	serial_putc('\r'); serial_putc('\n');

	/* This code looks quite crappy but this way we don't
 	 * have to worry about running out of registers if we
 	 * occupy eax, ebx, ecx, edx at the same time
 	 */
	reg32 = cpuid_eax(eax, ecx);
	serial_put32(reg32);
	serial_putc('.');

	reg32 = cpuid_ebx(eax, ecx);
	serial_put32(reg32);
	serial_putc('.');

	reg32 = cpuid_ecx(eax, ecx);
	serial_put32(reg32);
	serial_putc('.');

	reg32 = cpuid_edx(eax, ecx);
	serial_put32(reg32);
}

static void serialice_mainboard(void)
{
	serial_putc('\r'); serial_putc('\n');

	/* must be defined in mainboard/<boardname>.c */
	serial_putstring(boardname);
}

static void serialice_version(void)
{
	serial_putstring("\nSerialICE v" VERSION " (" __DATE__ ")\n");
}

#define BINARY_READ_MEM8   0x00
#define BINARY_READ_MEM16  0x01
#define BINARY_READ_MEM32  0x02
#define BINARY_READ_MEM64  0x03
#define BINARY_WRITE_MEM8  0x10
#define BINARY_WRITE_MEM16 0x11
#define BINARY_WRITE_MEM32 0x12
#define BINARY_WRITE_MEM64 0x13
#define BINARY_READ_IO8    0x20
#define BINARY_READ_IO16   0x21
#define BINARY_READ_IO32   0x22
#define BINARY_WRITE_IO8   0x30
#define BINARY_WRITE_IO16  0x31
#define BINARY_WRITE_IO32  0x32
#define BINARY_RDMSR       0x40
#define BINARY_WRMSR       0x41
#define BINARY_CPUID       0x42

#define BINARY_NOP         0xaa
#define BINARY_EXIT        '~'

#define BINARY_ACK         0x55
#define BINARY_NAK         0xbb

static u16 binary_read16(void)
{
	u16 val;
	val = serial_read();
	val |= serial_read() << 8;
	return val;
}

static u32 binary_read32(void)
{
	u32 val;
	val = serial_read();
	val |= serial_read() << 8;
	val |= serial_read() << 16;
	val |= serial_read() << 24;
	return val;
}

static u64_t binary_read64(void)
{
	u64_t val;
	val.lo = binary_read32();
	val.hi = binary_read32();
	return val;
}

static void binary_write16(u16 val)
{
	serial_write(val & 0xff);
	serial_write(val >> 8 & 0xff);
}

static void binary_write32(u32 val)
{
	serial_write(val & 0xff);
	serial_write(val >> 8 & 0xff);
	serial_write(val >> 16 & 0xff);
	serial_write(val >> 24 & 0xff);
}

static void binary_write64(u64_t val)
{
	binary_write32(val.lo);
	binary_write32(val.hi);
}

static void binary_cpuid(void)
{
	u32 eax, ecx;
	u32 reg32;

	// Format:
	//    --EAX--- --ECX---
	// *ci00000000.00000000
	eax = binary_read32();
	ecx = binary_read32();

	/* This code looks quite crappy but this way we don't
 	 * have to worry about running out of registers if we
 	 * occupy eax, ebx, ecx, edx at the same time
 	 */
	reg32 = cpuid_eax(eax, ecx);
	binary_write32(reg32);

	reg32 = cpuid_ebx(eax, ecx);
	binary_write32(reg32);

	reg32 = cpuid_ecx(eax, ecx);
	binary_write32(reg32);

	reg32 = cpuid_edx(eax, ecx);
	binary_write32(reg32);
}


static void binary_main(void)
{
	u32 tmp;
	msr_t msr;

	serial_write(BINARY_ACK);
	for (;;)
		switch (serial_read()) {
		case BINARY_READ_MEM8:
			serial_write(read8(binary_read32()));
			serial_write(BINARY_ACK);
			break;
		case BINARY_READ_MEM16:
			binary_write16(read16(binary_read32()));
			serial_write(BINARY_ACK);
			break;
		case BINARY_READ_MEM32:
			binary_write32(read32(binary_read32()));
			serial_write(BINARY_ACK);
			break;
		case BINARY_READ_MEM64:
			binary_write64(read64(binary_read32()));
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRITE_MEM8:
			tmp = binary_read32();
			write8(tmp, serial_read());
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRITE_MEM16:
			tmp = binary_read32();
			write16(tmp, binary_read16());
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRITE_MEM32:
			tmp = binary_read32();
			write32(tmp, binary_read32());
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRITE_MEM64:
			tmp = binary_read32();
			write64(tmp, binary_read64());
			serial_write(BINARY_ACK);
			break;
		case BINARY_READ_IO8:
			serial_write(inb(binary_read16()));
			serial_write(BINARY_ACK);
			break;
		case BINARY_READ_IO16:
			binary_write16(inw(binary_read16()));
			serial_write(BINARY_ACK);
			break;
		case BINARY_READ_IO32:
			binary_write32(inl(binary_read16()));
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRITE_IO8:
			tmp = binary_read16();
			outb(serial_read(), tmp);
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRITE_IO16:
			tmp = binary_read16();
			outw(binary_read16(), tmp);
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRITE_IO32:
			tmp = binary_read16();
			outl(binary_read32(), tmp);
			serial_write(BINARY_ACK);
			break;
		case BINARY_RDMSR:
			msr = rdmsr(binary_read32(), 0);
			binary_write32(msr.lo);
			binary_write32(msr.hi);
			serial_write(BINARY_ACK);
			break;
		case BINARY_WRMSR:
			tmp = binary_read32();
			msr.lo = binary_read32();
			msr.hi = binary_read32();
			wrmsr(tmp, msr, 0);
			serial_write(BINARY_ACK);
			break;
		case BINARY_CPUID:
			binary_cpuid();
			serial_write(BINARY_ACK);
			break;
		case BINARY_NOP:
			serial_write(BINARY_ACK);
			break;
		case BINARY_EXIT:
			serial_write(BINARY_ACK);
			return;
		default:
			serial_write(BINARY_NAK);
			break;
		}
}

int main(void)
{
	chipset_init();

	serial_init();

	serialice_version();

	while(1) {
		u16 c;
		serial_putstring("\n> ");

		c = serial_getc();
		if (c != '*')
			continue;

		c = serial_getc() << 8;
		c |= serial_getc();

		switch(c) {
		case (('r' << 8)|'m'): // Read Memory *rm
			serialice_read_memory();
			break;
		case (('w' << 8)|'m'): // Write Memory *wm
			serialice_write_memory();
			break;
		case (('r' << 8)|'i'): // Read IO *ri
			serialice_read_io();
			break;
		case (('w' << 8)|'i'): // Write IO *wi
			serialice_write_io();
			break;
		case (('r' << 8)|'c'): // Read CPU MSR *rc
			serialice_read_msr();
			break;
		case (('w' << 8)|'c'): // Write CPU MSR *wc
			serialice_write_msr();
			break;
		case (('c' << 8)|'i'): // Read CPUID *ci
			serialice_cpuinfo();
			break;
		case (('m' << 8)|'b'): // Read mainboard type *mb
			serialice_mainboard();
			break;
		case (('v' << 8)|'i'): // Read version info *vi
			serialice_version();
			break;
		case (('e' << 8)|'b'): // Enter binary mode
			binary_main();
			break;
		default:
			serial_putstring("ERROR\n");
			break;
		}
	}

	// Never get here:
	return 0;
}
