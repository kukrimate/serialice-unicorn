/*
 * emu.cpp: Emulator
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <exception>

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
	auto emu = static_cast<Emulator *>(user_data);
	try {
		return emu->handle_io_read(port, size);
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(emu->m_uc);
		return 0;
	}
}

void Emulator::hook_io_write(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		static_cast<Emulator *>(user_data)->handle_io_write(port, size, value);
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(emu->m_uc);
	}
}

bool Emulator::hook_mem_read(uc_engine *uc, int type, uint64_t address, int size, int64_t value, void *user_data, uint64_t *result)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		*result = static_cast<Emulator *>(user_data)->handle_mem_read(address, size);
		return true;
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(emu->m_uc);
		return true;
	}
}

bool Emulator::hook_mem_write(uc_engine *uc, int type, uint64_t address, int size, int64_t value, void *user_data)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		static_cast<Emulator *>(user_data)->handle_mem_write(address, size, value);
		return true;
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(emu->m_uc);
		return true;
	}
}

bool Emulator::hook_rdmsr(uc_engine *uc, void *user_data)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		return static_cast<Emulator *>(user_data)->handle_rdmsr();
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(static_cast<Emulator *>(user_data)->m_uc);
		return true;
	}
}

bool Emulator::hook_wrmsr(uc_engine *uc, void *user_data)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		return static_cast<Emulator *>(user_data)->handle_wrmsr();
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(static_cast<Emulator *>(user_data)->m_uc);
		return true;
	}
}

bool Emulator::hook_cpuid(uc_engine *uc, void *user_data)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		return static_cast<Emulator *>(user_data)->handle_cpuid();
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(static_cast<Emulator *>(user_data)->m_uc);
		return true;
	}
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {}
bool Emulator::hook_rdtsc(uc_engine *uc, void *user_data)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		return static_cast<Emulator *>(user_data)->handle_rdtsc();
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(static_cast<Emulator *>(user_data)->m_uc);
		return true;
	}
}

bool Emulator::hook_rdtscp(uc_engine *uc, void *user_data)
{
	auto emu = static_cast<Emulator *>(user_data);
	try {
		return static_cast<Emulator *>(user_data)->handle_rdtscp();
	} catch (...) {
		emu->m_rethrow_me = std::current_exception();
		uc_emu_stop(static_cast<Emulator *>(user_data)->m_uc);
		return true;
	}
}


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
	if (port == 0x3f8 && size == 1) {
		unsigned char val = value;
		m_serial_out.write(&val, 1);
		return;
	}

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
	uint32_t addr = read_register(Register::ECX);

	int mux = m_filter.rdmsr_pre(*this, addr);

	if (mux & READ_FROM_SERIALICE) {
		// Get RDMSR result from target
		uint32_t hi = 0, lo = 0;
		m_target.rdmsr(addr, /*key=*/0, &hi, &lo);

		// Call post hook
		m_filter.rdmsr_post(*this, &hi, &lo);

		// Inject result into VM
		write_register(Register::EDX, hi);
		write_register(Register::EAX, lo);

		// Indicate we overrode RDMSR
		return true;
	}

	// Tell unicorn to execute RDMSR if requested
	// FIXME: we cannot call post hook here
	return !(mux & READ_FROM_QEMU);
}

bool Emulator::handle_wrmsr()
{
	uint32_t addr = read_register(Register::ECX);
	uint32_t hi = read_register(Register::EDX);
	uint32_t lo = read_register(Register::EAX);

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
	uint32_t eax = read_register(Register::EAX);
	uint32_t ecx = read_register(Register::ECX);

	int mux = m_filter.cpuid_pre(*this, eax, ecx);

	if (mux & READ_FROM_SERIALICE) {
		// Get CPUID result from target
		CpuidRegs regs = m_target.cpuid(eax, ecx);

		// Call post hook
		m_filter.cpuid_post(*this, regs);

		// Inject result into VM
		write_register(Register::EAX, regs.eax);
		write_register(Register::EBX, regs.ebx);
		write_register(Register::ECX, regs.ecx);
		write_register(Register::EDX, regs.edx);

		// Indicate that we overrode CPUID
		return true;
	}

	// Tell unicorn to execute CPUID if requested
	// FIXME: we cannot call post hook here
	return !(mux & READ_FROM_QEMU);
}

bool Emulator::handle_rdtsc()
{
	uint32_t eax, edx;
	// Get result from target
	m_target.rdtsc(&eax, &edx);
	// Inject result into VM
	write_register(Register::EAX, eax);
	write_register(Register::EDX, edx);
	return true;
}

bool Emulator::handle_rdtscp()
{
	uint32_t eax, edx, ecx;
	// Get result from target
	m_target.rdtscp(&eax, &edx, &ecx);
	// Inject result into VM
	write_register(Register::EAX, eax);
	write_register(Register::EDX, edx);
	write_register(Register::ECX, ecx);
	return true;
}

Emulator::Emulator(int cpu_type, Target &target, Filter &filter)
	: m_target(target)
	, m_filter(filter)
	, m_serial_out(FileHandle::create("serial.log", O_RDWR))
{
	uc_hook hh;
	// Create unicorn handle
	UC_DO(uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc));
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
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_rdtsc), this, 0, 0xffffffff, UC_X86_INS_RDTSC));
	UC_DO(uc_hook_add(m_uc, &hh, UC_HOOK_INSN, reinterpret_cast<void *>(hook_rdtscp), this, 0, 0xffffffff, UC_X86_INS_RDTSCP));
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
	case EAX: return UC_X86_REG_RAX;
	case ECX: return UC_X86_REG_RCX;
	case EDX: return UC_X86_REG_RDX;
	case EBX: return UC_X86_REG_RBX;
	case ESP: return UC_X86_REG_RSP;
	case EBP: return UC_X86_REG_RBP;
	case ESI: return UC_X86_REG_RSI;
	case EDI: return UC_X86_REG_RDI;
	case EIP: return UC_X86_REG_RIP;
	case CS: return UC_X86_REG_CS;
	default: abort();
	}
}

uint32_t Emulator::read_register(Register reg)
{
	uint64_t val = 0; /* NOTE u64 as we might be in long mode */
	UC_DO(uc_reg_read(m_uc, reg2uc(reg), &val));
	return val;
}

void Emulator::write_register(Register reg, uint32_t val)
{
	uint64_t v64 = val; /* NOTE u64 as we might be in long mode */
	UC_DO(uc_reg_write(m_uc, reg2uc(reg), &v64));
}

uint32_t Emulator::read_mem(uint32_t addr, int size)
{
	uint32_t val = 0;
	UC_DO(uc_mem_read(m_uc, addr, &val, size));
	return val;
}

void Emulator::start()
{
	// Start emulation at X86 reset vector
	// NOTE: We only set IP=0xfff0, hidden base of CS is set to 0xffff0000
	// by patching Unicorn Engine to always use the standard X86 reset vector
	UC_DO(uc_emu_start(m_uc, 0xfff0, 0, 0, 0));
	if (m_rethrow_me)
		std::rethrow_exception(m_rethrow_me);
}

void Emulator::dump_state()
{
	uint16_t cs = read_register(CS);
	uint32_t eip = read_register(EIP);
	uint32_t eax = read_register(EAX);
	uint32_t ebx = read_register(EBX);
	uint32_t ecx = read_register(ECX);
	uint32_t edx = read_register(EDX);
	uint32_t esi = read_register(ESI);
	uint32_t edi = read_register(EDI);
	uint32_t ebp = read_register(EBP);
	uint32_t esp = read_register(ESP);
	printf("Registers\n"
		"  CS:EIP %04x:%08x\n"
		"  EAX %08x EBX %08x ECX %08x EDX %08x\n"
		"  ESI %08x EDI %08x EBP %08x ESP %08x\n"
		"Stack (64 dwords starting at ESP)\n",
		cs, eip, eax, ebx, ecx, edx, esi, edi, ebp, esp);
	for (int i = 0; i < 64; ++i) {
		uint32_t addr = esp + i * 4;
		try {
			printf("  [%08x] = %08x\n", addr, read_mem(addr, 4));
		} catch (...) {
			break;
		}
	}
}
