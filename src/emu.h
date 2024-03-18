/*
 * emu.h: Emulator
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>

class Target;
class Filter;

struct uc_struct;
typedef struct uc_struct uc_engine;

enum Register { EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP, CS };

struct CpuidRegs { uint32_t eax, ebx, ecx, edx; };

class Emulator {
private:
	uc_engine *m_uc;
	Target &m_target;
	Filter &m_filter;

	// Captured exceptions inside a hook
	std::exception_ptr m_rethrow_me {};

	// Unicorn hooks (called by C)
	static uint32_t hook_io_read(uc_engine *uc, uint32_t port, int size, void *user_data);
	static void hook_io_write(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data);
	static bool hook_mem_read(uc_engine *uc, int type, uint64_t address, int size, int64_t value, void *user_data, uint64_t *result);
	static bool hook_mem_write(uc_engine *uc, int type, uint64_t address, int size, int64_t value, void *user_data);
	static bool hook_rdmsr(uc_engine *uc, void *user_data);
	static bool hook_wrmsr(uc_engine *uc, void *user_data);
	static bool hook_cpuid(uc_engine *uc, void *user_data);

	// C++ callbacks
	uint32_t handle_io_read(uint32_t port, int size);
	void handle_io_write(uint32_t port, int size, uint32_t value);
	uint64_t handle_mem_read(uint64_t addr, int size);
	void handle_mem_write(uint64_t addr, int size, uint64_t value);
	bool handle_rdmsr();
	bool handle_wrmsr();
	bool handle_cpuid();

public:
	Emulator(int cpu_type, Target &target, Filter &filter);
	~Emulator();

	void map_rom(void *data, uint64_t addr, size_t size);
	void map_ram(uint64_t addr, size_t size);
	void unmap(uint64_t addr, size_t size);

	uint32_t read_register(Register reg);
	void write_register(Register reg, uint32_t val);

	uint32_t read_mem(uint32_t addr, int size);

	void start();
};
