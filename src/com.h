/*
 * com.h: Target communication
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

struct CpuidRegs;

class Target {
private:
	int m_fd;
	char *m_buffer;
	char *m_command;

	int m_handshake_mode = 0;

	int serialice_read(void *buf, size_t nbyte);
	int serialice_write(const void *buf, size_t nbyte);
	int serialice_wait_prompt();

	void serialice_command(const char *command, int reply_len);

public:
	Target(const char *device);
	~Target();

	void version();
	std::string mainboard();
	uint64_t io_read(uint16_t port, unsigned int size);
	void io_write(uint16_t port, unsigned int size, uint64_t data);
	uint64_t load(uint32_t addr, unsigned int size);
	void store(uint32_t addr, unsigned int size, uint64_t data);
	void rdmsr(uint32_t addr, uint32_t key, uint32_t * hi, uint32_t * lo);
	void wrmsr(uint32_t addr, uint32_t key, uint32_t hi, uint32_t lo);
	CpuidRegs cpuid(uint32_t eax, uint32_t ecx);
};
