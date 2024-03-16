/*
 * emu.cpp: Emulator
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <exception>
#include <iostream>

#include <unicorn/unicorn.h>

#include "com.h"
#include "emu.h"
#include "filter.h"

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

uint32_t Emulator::hook_io_read(uc_engine *uc, uint32_t port, int size, void *user_data)
{
	return static_cast<Emulator *>(user_data)->handle_io_read(port, size);
}

void Emulator::hook_io_write(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
	static_cast<Emulator *>(user_data)->handle_io_write(port, size, value);
}

bool Emulator::hook_mem_read(uc_engine *uc, int type, uint64_t address, int size, int64_t value, void *user_data, uint64_t *result)
{
	*result = static_cast<Emulator *>(user_data)->handle_mem_read(address, size);
	return true; // We have Handled the read
}

bool Emulator::hook_mem_write(uc_engine *uc, int type, uint64_t address, int size, int64_t value, void *user_data)
{
	static_cast<Emulator *>(user_data)->handle_mem_write(address, size, value);
	return true; // Handled have the write
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

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {}

#define mask_data(val,bytes) (val & (((uint64_t)1<<(bytes*8))-1))

uint32_t Emulator::handle_io_read(uint32_t port, int size)
{
	uint64_t value = 0;
	int mux = m_filter.io_read_pre(*this, port, size);

	if (mux & READ_FROM_SERIALICE)
		value = m_target.io_read(port, size);
	if (mux & READ_FROM_QEMU) // FIXME
		;

	value = mask_data(value, size);
	m_filter.io_read_post(*this, &value);
	return value;
}

void Emulator::handle_io_write(uint32_t port, int size, uint32_t value)
{
	value = mask_data(value, size);
	uint64_t v64 = value;
	int mux = m_filter.io_write_pre(*this, &v64, port, size);
	value = v64;
	value = mask_data(value, size);

	if (mux & WRITE_TO_SERIALICE)
		m_target.io_write(port, size, value);
	if (mux & WRITE_TO_QEMU) // FIXME
		;

	m_filter.io_write_post(*this);
}

uint64_t Emulator::handle_mem_read(uint64_t addr, int size)
{
	uint64_t data = 0;

	int mux = m_filter.load_pre(*this, addr, size);

	if (mux & READ_FROM_SERIALICE)
		data = m_target.load(addr, size);
	if (mux & READ_FROM_QEMU) // FIXME
		;

	m_filter.load_post(*this, &data);

	return data;
}

void Emulator::handle_mem_write(uint64_t addr, int size, uint64_t value)
{
	int mux = m_filter.store_pre(*this, addr, size, &value);

	if (mux & WRITE_TO_SERIALICE)
		m_target.store(addr, size, value);
	if (mux & WRITE_TO_QEMU) // FIXME
		;

	m_filter.store_post(*this);
}

bool Emulator::handle_rdmsr()
{
	uint32_t addr;
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_ECX, (void *) &addr));

	int mux = m_filter.rdmsr_pre(*this, addr);

	if (mux & READ_FROM_SERIALICE) {
		// Get RDMSR result from target
		uint32_t hi = 0, lo = 0;
		m_target.rdmsr(addr, /*key=*/0, &hi, &lo);

		// Call post hook
		m_filter.rdmsr_post(*this, &hi, &lo);

		// Inject result into VM
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EDX, (void *) &hi));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EAX, (void *) &lo));

		// Indicate we overrode RDMSR
		return true;
	}

	// Tell unicorn to execute RDMSR if requested
	// FIXME: we cannot call post hook here
	return !(mux & READ_FROM_QEMU);
}

bool Emulator::handle_wrmsr()
{
	uint32_t addr, hi, lo;
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_ECX, (void *) &addr));
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_EDX, (void *) &hi));
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_EAX, (void *) &lo));

	int mux = m_filter.wrmsr_pre(*this, addr, &hi, &lo);

	// Execute WRMSR on target if requested
	if (mux & WRITE_TO_SERIALICE)
		m_target.wrmsr(addr, /*key=*/0, hi, lo);

	// Call post hook
	m_filter.wrmsr_post(*this);

	// Execute WRMSR in VM if requested
	return !(mux & WRITE_TO_QEMU);
}

bool Emulator::handle_cpuid()
{
	uint32_t eax, ecx;
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_EAX, (void *) &eax));
	UC_DO(uc_reg_read(m_uc, UC_X86_REG_ECX, (void *) &ecx));

	int mux = m_filter.cpuid_pre(*this, eax, ecx);

	if (mux & READ_FROM_SERIALICE) {
		// Get CPUID result from target
		CpuidRegs regs = m_target.cpuid(eax, ecx);

		// Call post hook
		m_filter.cpuid_post(*this, regs);

		// Inject result into VM
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EAX, (void *) &regs.eax));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EBX, (void *) &regs.ebx));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_ECX, (void *) &regs.ecx));
		UC_DO(uc_reg_write(m_uc, UC_X86_REG_EDX, (void *) &regs.edx));

		// Indicate that we overrode CPUID
		return true;
	}

	// Tell unicorn to execute CPUID if requested
	// FIXME: we cannot call post hook here
	return !(mux & READ_FROM_QEMU);
}


Emulator::Emulator(int cpu_type, Target &target, Filter &filter)
	: m_target(target)
	, m_filter(filter)
{
	uc_hook hh;
	// Create unicorn handle
	UC_DO(uc_open(UC_ARCH_X86, UC_MODE_16, &m_uc));
	// Set CPU type
	UC_DO(uc_ctl(m_uc, UC_CTL_CPU_MODEL, static_cast<uc_cpu_x86>(cpu_type)));
	// Install hooks
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_io_read), this, 0, 0xffffffff, UC_X86_INS_IN));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_io_write), this, 0, 0xffffffff, UC_X86_INS_OUT));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_MEM_READ_UNMAPPED, reinterpret_cast<void *>(hook_mem_read), this, 0, 0xffffffff));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_MEM_WRITE_UNMAPPED, reinterpret_cast<void *>(hook_mem_write), this, 0, 0xffffffff));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_rdmsr), this, 0, 0xffffffff, UC_X86_INS_RDMSR));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_wrmsr), this, 0, 0xffffffff, UC_X86_INS_WRMSR));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_cpuid), this, 0, 0xffffffff, UC_X86_INS_CPUID));
	// We need to trace every instruction to accurately track the guest the instruction pointer.
	// This shouldn't cause any real performance issues as serial communication is by far our biggest bottleneck.
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

static uc_x86_reg reg2uc(Register reg)
{
	switch (reg) {
	case EAX: return UC_X86_REG_EAX;
	case ECX: return UC_X86_REG_ECX;
	case EDX: return UC_X86_REG_EDX;
	case EBX: return UC_X86_REG_EBX;
	case ESP: return UC_X86_REG_ESP;
	case EBP: return UC_X86_REG_EBP;
	case ESI: return UC_X86_REG_ESI;
	case EDI: return UC_X86_REG_EDI;
	case EIP: return UC_X86_REG_EIP;
	case CS: return UC_X86_REG_CS;
	default: abort();
	}
}

uint32_t Emulator::read_register(Register reg)
{
	uint32_t val;
	UC_DO(uc_reg_read(m_uc, reg2uc(reg), &val));
	if (reg == CS)
		val &= 0xffff;
	return val;
}

void Emulator::write_register(Register reg, uint32_t val)
{
	UC_DO(uc_reg_write(m_uc, reg2uc(reg), &val));
}

void Emulator::start()
{
	// Start emulation at X86 reset vector
	// NOTE: We only set IP=0xfff0, hidden base of CS is set to 0xffff0000
	// by patching Unicorn Engine to always use the standard X86 reset vector
	UC_DO(uc_emu_start(m_uc, 0xfff0, 0, 0, 0));
}
