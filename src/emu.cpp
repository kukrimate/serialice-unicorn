/*
 * serialice-com.cpp: Emulator
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <exception>
#include <iostream>

#include <unicorn/unicorn.h>

#include "serialice.h"

class UcException : public std::exception {
private:
	uc_err m_err;
public:
	UcException(uc_err err)
		: m_err(err)
	{}

	virtual const char *what() const noexcept override
	{
		return uc_strerror(m_err);
	}
};

#define UC_DO(action) \
	do { \
		if (auto err = action; err != UC_ERR_OK) \
			throw UcException(err); \
	} while (false)

Target *g_target;
Filter *g_filter;

uint32_t Emulator::hook_io_read(uc_engine *uc, uint32_t port, int size, void *user_data)
{
	return static_cast<Emulator *>(user_data)->handle_io_read(port, size);
}

void Emulator::hook_io_write(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{

	static_cast<Emulator *>(user_data)->handle_io_write(port, size, value);
}


uint64_t Emulator::hook_mem_read_0(uc_engine *uc, uint64_t offset, unsigned size, void *user_data)
{
	std::cout << "fuck" << std::endl;
	return static_cast<Emulator *>(user_data)->handle_mem_read(offset, size);
}

void Emulator::hook_mem_write_0(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data)
{
	static_cast<Emulator *>(user_data)->handle_mem_write(offset, size, value);
}

uint64_t Emulator::hook_mem_read_1m(uc_engine *uc, uint64_t offset, unsigned size, void *user_data)
{
	return static_cast<Emulator *>(user_data)->handle_mem_read(1 * MiB + offset, size);
}

void Emulator::hook_mem_write_1m(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data)
{
	static_cast<Emulator *>(user_data)->handle_mem_write(1 * MiB + offset, size, value);
}

bool Emulator::hook_rdmsr(uc_engine *uc, void *user_data)
{
	return static_cast<Emulator *>(user_data)->handle_rdmsr();
}

bool Emulator::hook_wrmsr(uc_engine *uc, void *user_data)
{
	return static_cast<Emulator *>(user_data)->handle_wrmsr();
}

bool Emulator::hook_cpuid(uc_engine *uc, void *user_data)
{
	return static_cast<Emulator *>(user_data)->handle_cpuid();
}

void Emulator::hook_und(uc_engine *uc)
{
	uint32_t cs, eip;

	UC_DO(uc_reg_read(uc, UC_X86_REG_CS, &cs));
	UC_DO(uc_reg_read(uc, UC_X86_REG_EIP, &eip));

	std::cout << "Invalid insn at " << std::hex << cs << ":" << eip << std::dec << std::endl;
}


bool Emulator::hook_unmap(uc_engine *uc, int type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data)
{
	uint32_t cs, eip;

	UC_DO(uc_reg_read(uc, UC_X86_REG_CS, &cs));
	UC_DO(uc_reg_read(uc, UC_X86_REG_EIP, &eip));

	std::cout << std::hex << cs << ":" << eip << ": unmapped access " << address << std::dec << std::endl;
	return false;
}

bool Emulator::hook_prot(uc_engine *uc, int type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data)
{
	uint32_t cs, eip;

	UC_DO(uc_reg_read(uc, UC_X86_REG_CS, &cs));
	UC_DO(uc_reg_read(uc, UC_X86_REG_EIP, &eip));

	std::cout << std::hex << cs << ":" << eip << ": prot access " << address << std::dec << std::endl;
	return false;
}


static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {}

Emulator::Emulator()
{
	uc_hook hh;
	// Create unicorn handle
	UC_DO(uc_open(UC_ARCH_X86, UC_MODE_16, &m_uc));
	// Make it Skylake
	UC_DO(uc_ctl(m_uc, UC_CTL_CPU_MODEL, UC_CPU_X86_SKYLAKE_CLIENT));
	// Install hooks
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_io_read), this, 0, 0xffffffff, UC_X86_INS_IN));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_io_write), this, 0, 0xffffffff, UC_X86_INS_OUT));

	// UC_DO(uc_mmio_map(m_uc, 0, 1 * MiB - 128 * KiB, hook_mem_read_0, this, hook_mem_write_0, this));
	UC_DO(uc_mmio_map(m_uc, 1 * MiB, 0xfef00000 - 1 * MiB, hook_mem_read_1m, this, hook_mem_write_1m, this));

	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_rdmsr), this, 0, 0xffffffff, UC_X86_INS_RDMSR));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_wrmsr), this, 0, 0xffffffff, UC_X86_INS_WRMSR));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_cpuid), this, 0, 0xffffffff, UC_X86_INS_CPUID));

	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN_INVALID, reinterpret_cast<void *>(hook_und), this, 0, 0xffffffff));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void *>(hook_unmap), this, 0, 0xffffffff));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_MEM_PROT, reinterpret_cast<void *>(hook_prot), this, 0, 0xffffffff));

	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_CODE, reinterpret_cast<void *>(hook_code), this, 0, 0xffffffff));
}

Emulator::~Emulator()
{
	uc_close(m_uc);
}

void Emulator::map_rom(void *data, uint64_t addr, size_t size)
{
	UC_DO(uc_mem_map_ptr(m_uc, addr, size, UC_PROT_ROM | UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, data));
}

void Emulator::map_ram(uint64_t addr, size_t size)
{
	UC_DO(uc_mem_map(m_uc, addr, size, UC_PROT_ALL));
}

void Emulator::unmap(uint64_t addr, size_t size)
{
	UC_DO(uc_mem_unmap(m_uc, addr, size));
}

void Emulator::start()
{
	UC_DO(uc_emu_start(m_uc, 0xfff0, 0, 0, 0));
}

#define mask_data(val,bytes) (val & (((uint64_t)1<<(bytes*8))-1))

uint32_t Emulator::handle_io_read(uint32_t port, int size)
{
	uint64_t value = 0;
	int mux = g_filter->io_read_pre(port, size);

	// NOTE: unicorn doesnt give us any I/O devices
	if (mux & READ_FROM_QEMU)
		value = 0xff;
	if (mux & READ_FROM_SERIALICE)
		value = g_target->io_read(port, size);

	value = mask_data(value, size);
	g_filter->io_read_post(&value);
	return value;
}

void Emulator::handle_io_write(uint32_t port, int size, uint32_t value)
{
	value = mask_data(value, size);
	uint64_t v64 = value;
	int mux = g_filter->io_write_pre(&v64, port, size);
	value = v64;
	value = mask_data(value, size);

	// NOTE: unicorn doesnt give us any I/O devices
	if (mux & WRITE_TO_QEMU)
		;
	if (mux & WRITE_TO_SERIALICE)
		g_target->io_write(port, size, value);

	g_filter->io_write_post();
}

uint64_t Emulator::handle_mem_read(uint64_t addr, int size)
{
	uint64_t data = 0;

	int mux = g_filter->load_pre(addr, size);

	if (mux & READ_FROM_SERIALICE)
		data = g_target->load(addr, size);
	if (mux & READ_FROM_QEMU)	// No real way for us to do that
		abort();

	g_filter->load_post(&data);

	return data;
}

void Emulator::handle_mem_write(uint64_t addr, int size, uint64_t value)
{
	int mux = g_filter->store_pre(addr, size, &value);

	if (mux & WRITE_TO_SERIALICE)
		g_target->store(addr, size, value);
	if (mux & WRITE_TO_QEMU)	// No real way for us to do that
		abort();

	g_filter->store_post();
}

bool Emulator::handle_rdmsr()
{
	uint32_t addr;
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_ECX, (void *) &addr));

	int mux = g_filter->rdmsr_pre(addr);

	if (mux & READ_FROM_SERIALICE) {
		// Get rdmsr result from target
		uint32_t hi = 0, lo = 0;
		g_target->rdmsr(addr, /*key=*/0, &hi, &lo);

		// Call post hook
		g_filter->rdmsr_post(&hi, &lo);

		// Write to vm
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EDX, (void *) &hi));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EAX, (void *) &lo));

		// Indicate we overrode rdmsr
		return true;
	}

	if (!(mux & READ_FROM_QEMU))	// FIXME: this must be the case now
		abort();

	// FIXME: we cannot call post hook here
	// g_filter->rdmsr_post(&hi, &lo);

	// Tell unicorn to execute rdmsr
	return false;
}

bool Emulator::handle_wrmsr()
{
	uint32_t addr, hi, lo;
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_ECX, (void *) &addr));
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_EDX, (void *) &hi));
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_EAX, (void *) &lo));

	int mux = g_filter->wrmsr_pre(addr, &hi, &lo);

	if (mux & WRITE_TO_SERIALICE) {
		// Run wrmsr on target
		g_target->wrmsr(addr, /*key=*/0, hi, lo);

		// Call post hook
		g_filter->wrmsr_post();

		// Indicate we overrode wrmsr
		return true;
	}

	// FIXME: we cannot call post hook here
	// g_filter->wrmsr_post();

	// Execute wrmsr if mux & WRITE_TO_QEMU
	return !(mux & WRITE_TO_QEMU);
}

bool Emulator::handle_cpuid()
{
	uint32_t eax, ecx;
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_EAX, (void *) &eax));
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_ECX, (void *) &ecx));

	int mux = g_filter->cpuid_pre(eax, ecx);

	if (mux & READ_FROM_SERIALICE) {
		// Get cpuid from target
		cpuid_regs_t regs;
		g_target->cpuid(eax, ecx, &regs);

		// Call post hook
		g_filter->cpuid_post(&regs);

		// Write to vm
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EAX, (void *) &regs.eax));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EBX, (void *) &regs.ebx));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_ECX, (void *) &regs.ecx));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EDX, (void *) &regs.edx));

		// Indicate that we overrode cpuid
		return true;
	}

	if (!(mux & READ_FROM_QEMU))	// FIXME: this must be the case now
		abort();

	// FIXME: we cannot call post hook here
	// g_filter->cpuid_post(&ret);

	// Tell unicorn to execute CPUID
	return false;

}
