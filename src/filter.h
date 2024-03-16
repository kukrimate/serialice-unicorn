/*
 * serialice.h: Definitions
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

struct lua_State;
struct CpuidRegs;

class Emulator;

#define READ_FROM_QEMU		(1 << 0)
#define READ_FROM_SERIALICE	(1 << 1)

#define WRITE_TO_QEMU		(1 << 0)
#define WRITE_TO_SERIALICE	(1 << 1)

class Filter {
private:
	const char *m_script;
	lua_State *L;

	void serialice_lua_registers();

public:
	Filter(
		const char *script,
		const char *mainboard,
		size_t rom_size);
	~Filter();

	void init_with_emulator(Emulator &emulator);

	std::optional<std::string> execute(Emulator &emulator, const std::string &cmd);

	int io_read_pre(Emulator &emulator, uint16_t port, int size);
	void io_read_post(Emulator &emulator, uint64_t *data);
	int io_write_pre(Emulator &emulator, uint64_t *data, uint16_t port, int size);
	void io_write_post(Emulator &emulator);

	int load_pre(Emulator &emulator, uint32_t addr, int size);
	void load_post(Emulator &emulator, uint64_t *data);
	int store_pre(Emulator &emulator, uint32_t addr, int size, uint64_t *data);
	void store_post(Emulator &emulator);

	int rdmsr_pre(Emulator &emulator, uint32_t addr);
	void rdmsr_post(Emulator &emulator, uint32_t *hi, uint32_t *lo);
	int wrmsr_pre(Emulator &emulator, uint32_t addr, uint32_t *hi, uint32_t *lo);
	void wrmsr_post(Emulator &emulator);

	int cpuid_pre(Emulator &emulator, uint32_t eax, uint32_t ecx);
	void cpuid_post(Emulator &emulator, CpuidRegs &res);
};
