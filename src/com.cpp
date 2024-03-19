/*
 * com.cpp: Target communication
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "com.h"
#include "emu.h"

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

static const size_t BUFFER_SIZE = 1024;

// **************************************************************************
// low level communication with the SerialICE shell (serial communication)

void Target::serialice_read(void *buf, size_t nbyte)
{
	char *ptr = static_cast<char *>(buf);
	for (size_t bytes_read = 0; bytes_read < nbyte;) {
		auto ret = m_handle.read(ptr, nbyte - bytes_read);
		bytes_read += ret;
		ptr += ret;
	}
}

void Target::serialice_write(const void *buf, size_t nbyte)
{
	const char *ptr = static_cast<const char *>(buf);
	for (size_t bytes_written = 0; bytes_written < nbyte;) {
		auto ret = m_handle.write(ptr, nbyte - bytes_written);
		bytes_written += ret;
		ptr += ret;
	}

}

Target::Target(const char *device)
	: m_handle(device, O_RDWR | O_NOCTTY | O_NONBLOCK)
{
	m_handle.ioctl(TIOCEXCL);   // Exclusive mode
	m_handle.fcntl(F_SETFL, 0); // Blocking I/O

	struct termios options;
	m_handle.tcgetattr(&options);

	// Disable cooked mode
	cfmakeraw(&options);

	// Wait for as many bytes as the caller asks for
	// (E.g. this must be longer then the longest posible reply)
	options.c_cc[VMIN] = 100;
	// No timeout
	options.c_cc[VTIME] = 0;

	// 8 bits, no parity, one stop bit
	options.c_cflag &= ~(CSIZE | PARENB | CSTOPB);
	options.c_cflag |= CS8;

	// Set baudrate
	cfsetspeed(&options, B115200);

	m_handle.tcsetattr(TCSANOW, &options);

	m_buffer = new unsigned char[BUFFER_SIZE];
	memset(m_buffer, 0, BUFFER_SIZE);
	m_command = new unsigned char[BUFFER_SIZE];
	memset(m_command, 0, BUFFER_SIZE);

	// Perform handshake
	for (;;) {
		// Flush buffer
		m_handle.tcflush(TCIOFLUSH);
		// Trigger prompt (exiting binary mode if needed)
		serialice_write("~", 1);
		// Exit loop upon prompt
		serialice_read(m_buffer, 5);
		if (memcmp(m_buffer, "~\r\n> ", 5) == 0 ||
		    memcmp(m_buffer, "\x55\r\n> ", 5) == 0)
			break;
	}

	// Enter binary mode
	serialice_write("*eb", 3);
	serialice_read(m_buffer, 4);
	if (memcmp(m_buffer, "*eb\x55", 4) != 0)
		throw_fmt("Failed to enter binary mode");
}

Target::~Target()
{
	delete[] m_command;
	delete[] m_buffer;
}


void Target::serialice_command(std::string_view command, int reply_len)
{
	serialice_write(command.data(), command.length());
	serialice_read(m_buffer, reply_len);
	if (m_buffer[reply_len - 1] != BINARY_ACK)
		throw_fmt("Command reply does not end in ACK");
}

// **************************************************************************
// high level communication with the SerialICE shell

std::string Target::version()
{
	abort();
}

std::string Target::mainboard()
{
	abort();
}

uint64_t Target::io_read(uint16_t port, unsigned int size)
{
	m_command[1] = port & 0xff;
	m_command[2] = port >> 8 & 0xff;

	switch (size) {
	case 1:
		m_command[0] = BINARY_READ_IO8;
		serialice_command(std::string_view((char*)m_command, 3), 2);
		return (uint8_t) m_buffer[0];
	case 2:
		m_command[0] = BINARY_READ_IO16;
		serialice_command(std::string_view((char*)m_command, 3), 3);
		return (uint16_t) m_buffer[0] | (uint16_t) m_buffer[1] << 8;
	case 4:
		m_command[0] = BINARY_READ_IO32;
		serialice_command(std::string_view((char*)m_command, 3), 5);
		return (uint32_t) m_buffer[0] | (uint32_t) m_buffer[1] << 8 |
		       (uint32_t) m_buffer[2] << 16 | (uint32_t) m_buffer[3] << 24;
	default:
		throw_fmt("Unknown read access size %d @%08x\n", size, port);
	}
}

void Target::io_write(uint16_t port, unsigned int size, uint64_t data)
{
	m_command[1] = port & 0xff;
	m_command[2] = port >> 8 & 0xff;
	for (size_t i = 0; i < 8; ++i)
		m_command[3 + i] = data >> (8 * i) & 0xff;

	switch (size) {
	case 1:
		m_command[0] = BINARY_WRITE_IO8;
		serialice_command(std::string_view((char*)m_command, 4), 1);
		break;
	case 2:
		m_command[0] = BINARY_WRITE_IO16;
		serialice_command(std::string_view((char*)m_command, 5), 1);
		break;
	case 4:
		m_command[0] = BINARY_WRITE_IO32;
		serialice_command(std::string_view((char*)m_command, 7), 1);
		break;
	default:
		throw_fmt("Unknown write access size %d @%08x\n", size, port);
	}
}

uint64_t Target::load(uint32_t addr, unsigned int size)
{
	m_command[1] = addr & 0xff;
	m_command[2] = addr >> 8 & 0xff;
	m_command[3] = addr >> 16 & 0xff;
	m_command[4] = addr >> 24 & 0xff;

	switch (size) {
	case 1:
		m_command[0] = BINARY_READ_MEM8;
		serialice_command(std::string_view((char*)m_command, 5), 2);
		return (uint8_t) m_buffer[0];
	case 2:
		m_command[0] = BINARY_READ_MEM16;
		serialice_command(std::string_view((char*)m_command, 5), 3);
		return (uint16_t) m_buffer[0] | (uint16_t) m_buffer[1] << 8;
	case 4:
		m_command[0] = BINARY_READ_MEM32;
		serialice_command(std::string_view((char*)m_command, 5), 5);
		return (uint32_t) m_buffer[0] | (uint32_t) m_buffer[1] << 8 |
		       (uint32_t) m_buffer[2] << 16 | (uint32_t) m_buffer[3] << 24;
	case 8:
		m_command[0] = BINARY_READ_MEM64;
		serialice_command(std::string_view((char*)m_command, 5), 9);
		return (uint64_t) m_buffer[0] | (uint64_t) m_buffer[1] << 8 |
		       (uint64_t) m_buffer[2] << 16 | (uint64_t) m_buffer[3] << 24 |
		       (uint64_t) m_buffer[4] << 32 | (uint64_t) m_buffer[5] << 40 |
		       (uint64_t) m_buffer[6] << 48 | (uint64_t) m_buffer[7] << 56;
	default:
		throw_fmt("Unknown read access size %d @%08x\n", size, addr);
	}
	return 0;
}

void Target::store(uint32_t addr, unsigned int size, uint64_t data)
{
	m_command[1] = addr & 0xff;
	m_command[2] = addr >> 8 & 0xff;
	m_command[3] = addr >> 16 & 0xff;
	m_command[4] = addr >> 24 & 0xff;
	for (size_t i = 0; i < 8; ++i)
		m_command[5 + i] = data >> (8 * i) & 0xff;

	switch (size) {
	case 1:
		m_command[0] = BINARY_WRITE_MEM8;
		serialice_command(std::string_view((char*)m_command, 6), 1);
		break;
	case 2:
		m_command[0] = BINARY_WRITE_MEM16;
		serialice_command(std::string_view((char*)m_command, 7), 1);
		break;
	case 4:
		m_command[0] = BINARY_WRITE_MEM32;
		serialice_command(std::string_view((char*)m_command, 9), 1);
		break;
	case 8:
		m_command[0] = BINARY_WRITE_MEM64;
		serialice_command(std::string_view((char*)m_command, 13), 1);
		break;
	default:
		throw_fmt("Unknown write access size %d @%08x\n", size, addr);
	}
}

void Target::rdmsr(uint32_t addr, uint32_t key, uint32_t *hi, uint32_t *lo)
{
	m_command[0] = BINARY_RDMSR;

	m_command[1] = addr & 0xff;
	m_command[2] = addr >> 8 & 0xff;
	m_command[3] = addr >> 16 & 0xff;
	m_command[4] = addr >> 24 & 0xff;

	serialice_command(std::string_view((char*)m_command, 5), 9);

	*lo = (uint32_t) m_buffer[0] | (uint32_t) m_buffer[1] << 8 |
	      (uint32_t) m_buffer[2] << 16 | (uint32_t) m_buffer[3] << 24;

	*hi =  (uint32_t) m_buffer[4] | (uint32_t) m_buffer[5] << 8 |
	       (uint32_t) m_buffer[6] << 16 | (uint32_t) m_buffer[7] << 24;
}

void Target::wrmsr(uint32_t addr, uint32_t key, uint32_t hi, uint32_t lo)
{
	m_command[0] = BINARY_WRMSR;

	m_command[1] = addr & 0xff;
	m_command[2] = addr >> 8 & 0xff;
	m_command[3] = addr >> 16 & 0xff;
	m_command[4] = addr >> 24 & 0xff;

	m_command[5] = lo & 0xff;
	m_command[6] = lo >> 8 & 0xff;
	m_command[7] = lo >> 16 & 0xff;
	m_command[8] = lo >> 24 & 0xff;

	m_command[9] = hi & 0xff;
	m_command[10] = hi >> 8 & 0xff;
	m_command[11] = hi >> 16 & 0xff;
	m_command[12] = hi >> 24 & 0xff;

	serialice_command(std::string_view((char*)m_command, 13), 1);
}

CpuidRegs Target::cpuid(uint32_t eax, uint32_t ecx)
{
	m_command[0] = BINARY_CPUID;

	m_command[1] = eax & 0xff;
	m_command[2] = eax >> 8 & 0xff;
	m_command[3] = eax >> 16 & 0xff;
	m_command[4] = eax >> 24 & 0xff;

	m_command[5] = ecx & 0xff;
	m_command[6] = ecx >> 8 & 0xff;
	m_command[7] = ecx >> 16 & 0xff;
	m_command[8] = ecx >> 24 & 0xff;

	serialice_command(std::string_view((char*)m_command, 9), 17);

	return {
		// FIXME: endianness
		*reinterpret_cast<uint32_t*>(m_buffer),
		*reinterpret_cast<uint32_t*>(m_buffer+4),
		*reinterpret_cast<uint32_t*>(m_buffer+8),
		*reinterpret_cast<uint32_t*>(m_buffer+12),
	};
}
