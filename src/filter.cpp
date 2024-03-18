/*
 * filter.cpp: Lua filter integration
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <cstring>
#include <optional>

#define LUA_COMPAT_5_2
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "emu.h"
#include "filter.h"
#include "misc.h"

// FIXME: this is an ugly way to expose emulator to Lua callbacks
static thread_local Emulator *g_emulator = nullptr;

// **************************************************************************
// LUA scripting interface and callbacks

static int serialice_register_physical(lua_State *L)
{
	if (lua_gettop(L) != 2) {
		lua_pushstring(L, "ERROR: Not called as SerialICE_register_physical(<addr> <size>)");
		lua_error(L);
		return 0;
	}

	uint32_t addr = lua_tointeger(L, 1);
	uint32_t size = lua_tointeger(L, 2);
	g_emulator->map_ram(addr, size);
	return 1;
}

static int serialice_system_reset(lua_State *L)
{
	lua_pushstring(L, "ERROR: SerialICE_system_reset() not supported");
	lua_error(L);
	return 0;
}

// **************************************************************************
// LUA register access

static std::optional<Register> str2reg(const char *s)
{
	if (strcasecmp(s, "eax") == 0) return EAX;
	if (strcasecmp(s, "ecx") == 0) return ECX;
	if (strcasecmp(s, "edx") == 0) return EDX;
	if (strcasecmp(s, "ebx") == 0) return EBX;
	if (strcasecmp(s, "esp") == 0) return ESP;
	if (strcasecmp(s, "ebp") == 0) return EBP;
	if (strcasecmp(s, "esi") == 0) return ESI;
	if (strcasecmp(s, "edi") == 0) return EDI;
	if (strcasecmp(s, "eip") == 0) return EIP;
	if (strcasecmp(s, "cs") == 0) return CS;
	return {};
}

static int register_set(lua_State *L)
{
	const char *s = luaL_checkstring(L, 2);
	uint32_t val = luaL_checkinteger(L, 3);

	if (auto reg = str2reg(s)) {
		g_emulator->write_register(*reg, val);
		return 1;
	}

	lua_pushstring(L, "No such register.");
	lua_error(L);
	return 0;
}

static int register_get(lua_State *L)
{
	const char *s = luaL_checkstring(L, 2);
	if (auto reg = str2reg(s)) {
		uint32_t val = g_emulator->read_register(*reg);
		lua_pushinteger(L, val);
		return 1;
	}

	lua_pushstring(L, "No such register.");
	lua_error(L);
	return 0;
}

void Filter::serialice_lua_registers()
{
	const struct luaL_Reg registermt[] = {
		{"__index", register_get},
		{"__newindex", register_set},
		{NULL, NULL}
	};

	lua_newuserdata(L, sizeof(void *));
	luaL_newmetatable(L, "registermt");
	luaL_setfuncs(L, registermt, 0);
	lua_setmetatable(L, -2);
	lua_setglobal(L, "regs");
}

Filter::Filter(
	const char *script,
	const char *mainboard,
	size_t rom_size)
{
	// Create a LUA context and load LUA libraries
	L = luaL_newstate();
	luaL_openlibs(L);

	// Setup globals
	lua_register(L, "SerialICE_register_physical", serialice_register_physical);
	lua_register(L, "SerialICE_system_reset", serialice_system_reset);

	lua_pushstring(L, mainboard);
	lua_setglobal(L, "SerialICE_mainboard");

	lua_pushinteger(L, rom_size);
	lua_setglobal(L, "SerialICE_rom_size");

	serialice_lua_registers();

	m_script = script;
}

Filter::~Filter()
{
	lua_close(L);
}

void Filter::init_with_emulator(Emulator &emulator)
{
	g_emulator = &emulator;

	// Load script
	if (luaL_loadfile(L, m_script))
		throw_fmt("Couldn't load SerialICE script: %s", lua_tostring(L, -1));

	// Run script
	if (lua_pcall(L, 0, 1, 0))
		throw_fmt("Failed to run script: %s", lua_tostring(L, -1));

	lua_pop(L, 1);
}

std::optional<std::string> Filter::execute(Emulator &emulator, const std::string &cmd)
{
	g_emulator = &emulator;

	if (luaL_loadbuffer(L, cmd.c_str(), cmd.length(), "line") || lua_pcall(L, 0, 0, 0)) {
		std::string err = lua_tostring(L, -1);
		lua_pop(L, 1);
		return err;
	}
	return {};
}

int Filter::io_read_pre(Emulator &emulator, uint16_t port, int size)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_io_read_filter");
	lua_pushinteger(L, port);
	lua_pushinteger(L, size);
	if (lua_pcall(L, 2, 2, 0))
		throw_fmt("Failed to run SerialICE_io_read_filter: %s", lua_tostring(L, -1));
	int ret = 0;
	ret |= lua_toboolean(L, -1) ? READ_FROM_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? READ_FROM_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

int Filter::io_write_pre(Emulator &emulator, uint64_t * data, uint16_t port, int size)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_io_write_filter");
	lua_pushinteger(L, port);
	lua_pushinteger(L, size);
	lua_pushinteger(L, *data);
	if (lua_pcall(L, 3, 3, 0))
		throw_fmt("Failed to run SerialICE_io_write_filter: %s", lua_tostring(L, -1));
	*data = lua_tointeger(L, -1);
	int ret = 0;
	ret |= lua_toboolean(L, -2) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -3) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 3);
	return ret;
}

int Filter::load_pre(Emulator &emulator, uint32_t addr, int size)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_memory_read_filter");
	lua_pushinteger(L, addr);
	lua_pushinteger(L, size);
	if (lua_pcall(L, 2, 2, 0))
		throw_fmt("Failed run SerialICE_memory_read_filter: %s", lua_tostring(L, -1));
	int ret = 0;
	ret |= lua_toboolean(L, -1) ? READ_FROM_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? READ_FROM_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

int Filter::store_pre(Emulator &emulator, uint32_t addr, int size, uint64_t * data)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_memory_write_filter");
	lua_pushinteger(L, addr);
	lua_pushinteger(L, size);
	lua_pushinteger(L, *data);
	if (lua_pcall(L, 3, 3, 0))
		throw_fmt("Failed to run SerialICE_memory_write_filter: %s", lua_tostring(L, -1));
	*data = lua_tointeger(L, -1);
	int ret = 0;
	ret |= lua_toboolean(L, -2) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -3) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 3);
	return ret;
}

int Filter::wrmsr_pre(Emulator &emulator, uint32_t addr, uint32_t * hi, uint32_t * lo)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_msr_write_filter");
	lua_pushinteger(L, addr);
	lua_pushinteger(L, *hi);
	lua_pushinteger(L, *lo);
	if (lua_pcall(L, 3, 4, 0))
		throw_fmt("Failed to run SerialICE_msr_write_filter: %s", lua_tostring(L, -1));
	*lo = lua_tointeger(L, -1);
	*hi = lua_tointeger(L, -2);
	int ret = 0;
	ret |= lua_toboolean(L, -3) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -4) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 4);
	return ret;
}

int Filter::rdmsr_pre(Emulator &emulator, uint32_t addr)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_msr_read_filter");
	lua_pushinteger(L, addr);
	if (lua_pcall(L, 1, 2, 0))
		throw_fmt("Failed to run SerialICE_msr_read_filter: %s", lua_tostring(L, -1));
	int ret = 0;
	ret |= lua_toboolean(L, -1) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

int Filter::cpuid_pre(Emulator &emulator, uint32_t eax, uint32_t ecx)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_cpuid_filter");
	lua_pushinteger(L, eax);
	lua_pushinteger(L, ecx);
	if (lua_pcall(L, 2, 2, 0))
		throw_fmt("Failed to run SerialICE_cpuid_filter: %s", lua_tostring(L, -1));
	int ret = 0;
	ret |= lua_toboolean(L, -1) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

void Filter::load_post(Emulator &emulator, uint64_t *data)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_memory_read_log");
	lua_pushinteger(L, *data);
	if (lua_pcall(L, 1, 1, 0))
		throw_fmt("Failed to run SerialICE_memory_read_log: %s", lua_tostring(L, -1));
	*data = lua_tointeger(L, -1);
	lua_pop(L, 1);
}

void Filter::store_post(Emulator &emulator)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_memory_write_log");
	if (lua_pcall(L, 0, 0, 0))
		throw_fmt("Failed to run SerialICE_memory_write_log: %s", lua_tostring(L, -1));
}

void Filter::io_read_post(Emulator &emulator, uint64_t *data)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_io_read_log");
	lua_pushinteger(L, *data);
	if (lua_pcall(L, 1, 1, 0))
		throw_fmt("Failed to run SerialICE_io_read_log: %s", lua_tostring(L, -1));
	*data = lua_tointeger(L, -1);
	lua_pop(L, 1);
}

void Filter::io_write_post(Emulator &emulator)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_io_write_log");
	if (lua_pcall(L, 0, 0, 0))
		throw_fmt("Failed to run SerialICE_io_write_log: %s", lua_tostring(L, -1));
}

void Filter::wrmsr_post(Emulator &emulator)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_msr_write_log");
	if (lua_pcall(L, 0, 0, 0))
		throw_fmt("Failed to run SerialICE_msr_write_log: %s", lua_tostring(L, -1));
}

void Filter::rdmsr_post(Emulator &emulator, uint32_t *hi, uint32_t *lo)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_msr_read_log");
	lua_pushinteger(L, *hi);
	lua_pushinteger(L, *lo);
	if (lua_pcall(L, 2, 2, 0))
		throw_fmt("Failed to run SerialICE_msr_read_log: %s", lua_tostring(L, -1));
	*hi = lua_tointeger(L, -2);
	*lo = lua_tointeger(L, -1);
	lua_pop(L, 2);
}

void Filter::cpuid_post(Emulator &emulator, CpuidRegs &res)
{
	g_emulator = &emulator;

	lua_getglobal(L, "SerialICE_cpuid_log");
	lua_pushinteger(L, res.eax);
	lua_pushinteger(L, res.ebx);
	lua_pushinteger(L, res.ecx);
	lua_pushinteger(L, res.edx);
	if (lua_pcall(L, 4, 4, 0))
		throw_fmt("Failed to run function SerialICE_cpuid_log: %s", lua_tostring(L, -1));
	res.edx = lua_tointeger(L, -1);
	res.ecx = lua_tointeger(L, -2);
	res.ebx = lua_tointeger(L, -3);
	res.eax = lua_tointeger(L, -4);
	lua_pop(L, 4);
}
