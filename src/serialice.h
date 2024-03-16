/*
 * serialice.h: Definitions
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SERIALICE_H
#define SERIALICE_H

#include <stddef.h>
#include <stdint.h>
#include <string>

#define KiB 1024
#define MiB (1024 * 1024)
#define GiB (1024 * 1024 * 1024)

struct uc_struct;
typedef struct uc_struct uc_engine;
typedef struct lua_State lua_State;

#define READ_FROM_QEMU		(1 << 0)
#define READ_FROM_SERIALICE	(1 << 1)

#define WRITE_TO_QEMU		(1 << 0)
#define WRITE_TO_SERIALICE	(1 << 1)

typedef struct {
	uint32_t eax, ebx, ecx, edx;
} cpuid_regs_t;

class Emulator {
private:
	uc_engine *m_uc;

	static uint32_t hook_io_read(uc_engine *uc, uint32_t port, int size, void *user_data);
	static void hook_io_write(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data);
	static uint64_t hook_mem_read_0(uc_engine *uc, uint64_t offset, unsigned size, void *user_data);
	static void hook_mem_write_0(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data);
	static uint64_t hook_mem_read_1m(uc_engine *uc, uint64_t offset, unsigned size, void *user_data);
	static void hook_mem_write_1m(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data);
	static bool hook_rdmsr(uc_engine *uc, void *user_data);
	static bool hook_wrmsr(uc_engine *uc, void *user_data);
	static bool hook_cpuid(uc_engine *uc, void *user_data);

	static void hook_und(uc_engine *uc);
	static bool hook_unmap(uc_engine *uc, int type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data);
	static bool hook_prot(uc_engine *uc, int type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data);

	uint32_t handle_io_read(uint32_t port, int size);
	void handle_io_write(uint32_t port, int size, uint32_t value);
	uint64_t handle_mem_read(uint64_t addr, int size);
	void handle_mem_write(uint64_t addr, int size, uint64_t value);
	bool handle_rdmsr();
	bool handle_wrmsr();
	bool handle_cpuid();
public:
	Emulator();
	~Emulator();

	void map_rom(void *data, uint64_t addr, size_t size);
	void map_ram(uint64_t addr, size_t size);
	void unmap(uint64_t addr, size_t size);

	void start();
};

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
	void cpuid(uint32_t eax, uint32_t ecx, cpuid_regs_t * ret);
};


class Filter {
private:
	lua_State *L;

	void serialice_lua_registers();
	void read_post(int flags, uint64_t *data);
	void write_post(int flags);

public:
	Filter(
		const char *script,
		const char *mainboard,
		size_t rom_size);
	~Filter();

	std::string execute(const std::string &cmd);

	int io_read_pre(uint16_t port, int size);
	void io_read_post(uint64_t *data);
	int io_write_pre(uint64_t * data, uint16_t port, int size);
	void io_write_post(void);

	int load_pre(uint32_t addr, int size);
	void load_post(uint64_t * data);
	int store_pre(uint32_t addr, int size, uint64_t * data);
	void store_post(void);

	int rdmsr_pre(uint32_t addr);
	void rdmsr_post(uint32_t * hi, uint32_t * lo);
	int wrmsr_pre(uint32_t addr, uint32_t * hi, uint32_t * lo);
	void wrmsr_post(void);

	int cpuid_pre(uint32_t eax, uint32_t ecx);
	void cpuid_post(cpuid_regs_t *res);
};

#endif
