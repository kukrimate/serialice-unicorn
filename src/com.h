/*
 * com.h: Target communication
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include "misc.h"

struct CpuidRegs;

class Target {
private:
	FileHandle m_handle;

	unsigned char *m_buffer;
	unsigned char *m_command;

	void serialice_read(void *buf, size_t nbyte);
	void serialice_write(const void *buf, size_t nbyte);

	void serialice_command(std::string_view command, int reply_len);

public:
	Target(const char *device);
	~Target();

	std::string version();
	std::string mainboard();

	uint64_t io_read(uint16_t port, unsigned int size);
	void io_write(uint16_t port, unsigned int size, uint64_t data);
	uint64_t load(uint32_t addr, unsigned int size);
	void store(uint32_t addr, unsigned int size, uint64_t data);
	void rdmsr(uint32_t addr, uint32_t key, uint32_t * hi, uint32_t * lo);
	void wrmsr(uint32_t addr, uint32_t key, uint32_t hi, uint32_t lo);
	CpuidRegs cpuid(uint32_t eax, uint32_t ecx);
	void rdtsc(uint32_t *eax, uint32_t *edx);
	void rdtscp(uint32_t *eax, uint32_t *edx, uint32_t *ecx);
};
