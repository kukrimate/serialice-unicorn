/*
 * serialice-com.cpp: Target communication
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* System includes */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "serialice.h"

#define BUFFER_SIZE 1024

// **************************************************************************
// low level communication with the SerialICE shell (serial communication)

int Target::serialice_read(void *buf, size_t nbyte)
{
	char *ptr = static_cast<char *>(buf);
	size_t bytes_read = 0;

	while (1) {
		ssize_t ret = read(m_fd, ptr, nbyte - bytes_read);

		if (ret == -1 && errno == EINTR) {
			continue;
		}

		if (ret == -1) {
			break;
		}

		bytes_read += ret;
		ptr += ret;

		if (bytes_read >= nbyte) {
			break;
		}
	}

	return bytes_read;
}

int Target::serialice_write(const void *buf, size_t nbyte)
{
	const char *ptr = static_cast<const char *>(buf);

	for (size_t i = 0; i < nbyte; i++) {
		while (write(m_fd, ptr + i, 1) != 1)
			;
		char c;
		while (read(m_fd, &c, 1) != 1)
			;
		if (c != ptr[i] && !m_handshake_mode) {
			printf("Readback error! %x/%x\n", c, ptr[i]);
		}
	}

	return nbyte;
}

int Target::serialice_wait_prompt()
{
	char buf[3];
	int l = serialice_read(buf, 3);

	if (l == -1) {
		perror("SerialICE: Could not read from target");
		exit(1);
	}

	while (buf[0] != '\n' || buf[1] != '>' || buf[2] != ' ') {
		buf[0] = buf[1];
		buf[1] = buf[2];
		l = serialice_read(buf + 2, 1);
		if (l == -1) {
			perror("SerialICE: Could not read from target");
			exit(1);
		}
	}

	return 0;
}

Target::Target(const char *device)
{
	m_fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);

	if (m_fd == -1) {
		perror("SerialICE: Could not connect to target TTY");
		exit(1);
	}

	if (ioctl(m_fd, TIOCEXCL) == -1) {
		perror("SerialICE: TTY not exclusively available");
		exit(1);
	}

	if (fcntl(m_fd, F_SETFL, 0) == -1) {
		perror("SerialICE: Could not switch to blocking I/O");
		exit(1);
	}

	struct termios options;
	if (tcgetattr(m_fd, &options) == -1) {
		perror("SerialICE: Could not get TTY attributes");
		exit(1);
	}

	cfsetispeed(&options, B115200);
	cfsetospeed(&options, B115200);

	/* set raw input, 1 second timeout */
	options.c_cflag |= (CLOCAL | CREAD);
	options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	options.c_oflag &= ~OPOST;
	options.c_iflag |= IGNCR;
	options.c_cc[VMIN] = 0;
	options.c_cc[VTIME] = 100;

	tcsetattr(m_fd, TCSANOW, &options);

	tcflush(m_fd, TCIOFLUSH);

	m_buffer = new char[BUFFER_SIZE];
	memset(m_buffer, 0, BUFFER_SIZE);
	m_command = new char[BUFFER_SIZE];
	memset(m_command, 0, BUFFER_SIZE);

	printf("SerialICE: Waiting for handshake with target... ");
	fflush(stdout);

	m_handshake_mode = 1;         // Readback errors are to be expected in this phase.

	/* Trigger a prompt */
	serialice_write("@", 1);

	/* ... and wait for it to appear */
	if (serialice_wait_prompt() == 0) {
		printf("target alive!\n");
	} else {
		printf("target not ok!\n");
		exit(1);
	}

	/* Each serialice_command() waits for a prompt, so trigger one for the
	 * first command, as we consumed the last one for the handshake
	 */
	serialice_write("@", 1);

	m_handshake_mode = 0;         // from now on, warn about readback errors.
}

Target::~Target()
{
	delete[] m_command;
	delete[] m_buffer;
}

void Target::serialice_command(const char *command, int reply_len)
{
	int l;

	serialice_wait_prompt();

	serialice_write(command, strlen(command));

	memset(m_buffer, 0, reply_len + 1);        // clear enough of the buffer

	l = serialice_read(m_buffer, reply_len);

	if (l == -1) {
		perror("SerialICE: Could not read from target");
		exit(1);
	}
	// compensate for CR on the wire. Needed on Win32
	if (m_buffer[0] == '\r') {
		memmove(m_buffer, m_buffer + 1, reply_len);
		serialice_read(m_buffer + reply_len - 1, 1);
	}

	if (l != reply_len) {
		printf("SerialICE: command was not answered sufficiently: "
			   "(%d/%d bytes)\n'%s'\n", l, reply_len, m_buffer);
		exit(1);
	}
}

// **************************************************************************
// high level communication with the SerialICE shell

void Target::version()
{
	int len = 0;
	printf("SerialICE: Version.....: ");
	serialice_command("*vi", 0);

	memset(m_buffer, 0, BUFFER_SIZE);
	serialice_read(m_buffer, 1);
	serialice_read(m_buffer, 1);
	while (m_buffer[len++] != '\n') {
		serialice_read(m_buffer + len, 1);
	}
	m_buffer[len - 1] = '\0';

	printf("%s\n", m_buffer);
}

std::string Target::mainboard()
{
	int len = 31;

	printf("SerialICE: Mainboard...: ");
	serialice_command("*mb", 32);
	while (len && m_buffer[len] == ' ') {
		m_buffer[len--] = '\0';
	}
	printf("%s\n", m_buffer + 1);
	return m_buffer + 1;
}

uint64_t Target::io_read(uint16_t port, unsigned int size)
{
	switch (size) {
	case 1:
		sprintf(m_command, "*ri%04x.b", port);
		// command read back: "\n00" (3 characters)
		serialice_command(m_command, 3);
		return (uint8_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	case 2:
		sprintf(m_command, "*ri%04x.w", port);
		// command read back: "\n0000" (5 characters)
		serialice_command(m_command, 5);
		return (uint16_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	case 4:
		sprintf(m_command, "*ri%04x.l", port);
		// command read back: "\n00000000" (9 characters)
		serialice_command(m_command, 9);
		return strtoul(m_buffer + 1, (char **)NULL, 16);
	default:
		printf("WARNING: unknown read access size %d @%08x\n", size, port);
		return -1;
	}
}

void Target::io_write(uint16_t port, unsigned int size, uint64_t data)
{
	switch (size) {
	case 1:
		sprintf(m_command, "*wi%04x.b=%02x", port, (uint8_t) data);
		serialice_command(m_command, 0);
		return;
	case 2:
		sprintf(m_command, "*wi%04x.w=%04x", port, (uint16_t) data);
		serialice_command(m_command, 0);
		return;
	case 4:
		sprintf(m_command, "*wi%04x.l=%08x", port, (uint32_t)data);
		serialice_command(m_command, 0);
		return;
	default:
		printf("WARNING: unknown write access size %d @%08x\n", size, port);
	}
	return;
}

uint64_t Target::load(uint32_t addr, unsigned int size)
{
	switch (size) {
	case 1:
		sprintf(m_command, "*rm%08x.b", addr);
		// command read back: "\n00" (3 characters)
		serialice_command(m_command, 3);
		return (uint8_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	case 2:
		sprintf(m_command, "*rm%08x.w", addr);
		// command read back: "\n0000" (5 characters)
		serialice_command(m_command, 5);
		return (uint16_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	case 4:
		sprintf(m_command, "*rm%08x.l", addr);
		// command read back: "\n00000000" (9 characters)
		serialice_command(m_command, 9);
		return (uint32_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	case 8:
		sprintf(m_command, "*rm%08x.q", addr);
		// command read back: "\n0000000000000000" (17 characters)
		serialice_command(m_command, 17);
		return (uint64_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	default:
		printf("WARNING: unknown read access size %d @%08x\n", size, addr);
	}
	return 0;
}

void Target::store(uint32_t addr, unsigned int size, uint64_t data)
{
	switch (size) {
	case 1:
		sprintf(m_command, "*wm%08x.b=%02x", addr, (uint8_t) data);
		serialice_command(m_command, 0);
		break;
	case 2:
		sprintf(m_command, "*wm%08x.w=%04x", addr, (uint16_t) data);
		serialice_command(m_command, 0);
		break;
	case 4:
		sprintf(m_command, "*wm%08x.l=%08x", addr, (uint32_t)data);
		serialice_command(m_command, 0);
		break;
	case 8:
		sprintf(m_command, "*wm%08x.q=%016lx", addr, data);
		serialice_command(m_command, 0);
		break;
	default:
		printf("WARNING: unknown write access size %d @%08x\n", size, addr);
	}
}

void Target::rdmsr(uint32_t addr, uint32_t key, uint32_t * hi, uint32_t * lo)
{
	sprintf(m_command, "*rc%08x.%08x", addr, key);
	// command read back: "\n00000000.00000000" (18 characters)
	serialice_command(m_command, 18);
	m_buffer[9] = 0;           // . -> \0
	*hi = (uint32_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	*lo = (uint32_t) strtoul(m_buffer + 10, (char **)NULL, 16);
}

void Target::wrmsr(uint32_t addr, uint32_t key, uint32_t hi, uint32_t lo)
{
	sprintf(m_command, "*wc%08x.%08x=%08x.%08x", addr, key, hi, lo);
	serialice_command(m_command, 0);
}

void Target::cpuid(uint32_t eax, uint32_t ecx, cpuid_regs_t * ret)
{
	sprintf(m_command, "*ci%08x.%08x", eax, ecx);
	// command read back: "\n000006f2.00000000.00001234.12340324"
	// (36 characters)
	serialice_command(m_command, 36);
	m_buffer[9] = 0;           // . -> \0
	m_buffer[18] = 0;          // . -> \0
	m_buffer[27] = 0;          // . -> \0
	ret->eax = (uint32_t) strtoul(m_buffer + 1, (char **)NULL, 16);
	ret->ebx = (uint32_t) strtoul(m_buffer + 10, (char **)NULL, 16);
	ret->ecx = (uint32_t) strtoul(m_buffer + 19, (char **)NULL, 16);
	ret->edx = (uint32_t) strtoul(m_buffer + 28, (char **)NULL, 16);
}
