/*
 * filter.cpp: Lua filter integration
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* System includes */
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* LUA includes */
#define LUA_COMPAT_5_2
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* Local includes */
#include "serialice.h"

#define LOG_IO		1
#define LOG_MEMORY	2
#define LOG_MSR		4

Emulator *g_emulator;

// **************************************************************************
// LUA scripting interface and callbacks

static int serialice_register_physical(lua_State * luastate)
{
	int n = lua_gettop(luastate);
	if (n != 2) {
		fprintf(stderr, "ERROR: Not called as SerialICE_register_physical(<addr> <size>)\n");
		return 0;
	}

	uint32_t addr = lua_tointeger(luastate, 1);
	uint32_t size = lua_tointeger(luastate, 2);
	printf("Registering physical memory at 0x%08x (0x%08x bytes)\n", addr, size);
	// callback_register_ram(addr, size);
	g_emulator->map_ram(addr, size);
	return 0;
}

static int serialice_system_reset(lua_State * luastate)
{
	printf("Rebooting the emulated CPU\n");
	// callback_system_reset();
	return 0;
}

// **************************************************************************
// LUA register access

// static int str2reg(const char *key)
// {
// 	if (strcmp(key, "eax") == 0) return EAX;
// 	if (strcmp(key, "ecx") == 0) return ECX;
// 	if (strcmp(key, "edx") == 0) return EDX;
// 	if (strcmp(key, "ebx") == 0) return EBX;
// 	if (strcmp(key, "esp") == 0) return ESP;
// 	if (strcmp(key, "ebp") == 0) return EBP;
// 	if (strcmp(key, "esi") == 0) return ESI;
// 	if (strcmp(key, "edi") == 0) return EDI;
// 	if (strcmp(key, "eip") == 0) return EIP;
// 	if (strcmp(key, "cs") == 0) return CS;
// 	return -1;
// }

static int register_set(lua_State * L)
{
	const char *key = luaL_checkstring(L, 2);
	int val = luaL_checkinteger(L, 3);

	// int reg = str2reg(key);

	// if (reg < 0) {
	// 	lua_pushstring(L, "No such register.");
	// 	lua_error(L);
	// 	return 0;
	// }

	// if (reg == CS)
	// 	val <<= 4;

	// callback_set_register(reg, val);

	return 1;
}

static int register_get(lua_State * L)
{
	const char *key = luaL_checkstring(L, 2);

	// int reg = str2reg(key);

	// if (reg < 0) {
	// 	lua_pushstring(L, "No such register.");
	// 	lua_error(L);
	// 	return 0;
	// }

	// int val = callback_get_register(reg);

	// if (reg == CS)
	// 	val >>= 4;

	// lua_pushinteger(L, val);

	lua_pushinteger(L, 0);

	return 1;
}

#undef env

void Filter::serialice_lua_registers()
{
	const struct luaL_Reg registermt[] = {
		{"__index", register_get},
		{"__newindex", register_set},
		{NULL, NULL}
	};

	lua_newuserdata(L, sizeof(void *));
	luaL_newmetatable(L, "registermt");
#if LUA_VERSION_NUM <= 501
	luaL_register(L, NULL, registermt);
#elif LUA_VERSION_NUM >= 502
	luaL_setfuncs(L, registermt, 0);
#endif
	lua_setmetatable(L, -2);
	lua_setglobal(L, "regs");
}

Filter::Filter(
	const char *script,
	const char *mainboard,
	size_t rom_size)
{
	int status;

	printf("SerialICE: LUA init...\n");

	/* Create a LUA context and load LUA libraries */
	L = luaL_newstate();
	luaL_openlibs(L);

	/* Register C function callbacks */
	lua_register(L, "SerialICE_register_physical", serialice_register_physical);
	lua_register(L, "SerialICE_system_reset", serialice_system_reset);

	/* Set global variable SerialICE_mainboard */
	lua_pushstring(L, mainboard);
	lua_setglobal(L, "SerialICE_mainboard");

	/* Set global variable SerialICE_rom_size */
	lua_pushinteger(L, rom_size);
	lua_setglobal(L, "SerialICE_rom_size");

	/* Enable Register Access */
	serialice_lua_registers();

	/* Load the script file */
	status = luaL_loadfile(L, script);
	if (status) {
		fprintf(stderr, "Couldn't load SerialICE script: %s\n",
				lua_tostring(L, -1));
		exit(1);
	}

	/* Ask Lua to run our little script */
	status = lua_pcall(L, 0, 1, 0);
	if (status) {
		fprintf(stderr, "Failed to run script: %s\n", lua_tostring(L, -1));
		exit(1);
	}
	lua_pop(L, 1);
}

Filter::~Filter()
{
	lua_close(L);
}

std::string Filter::execute(const std::string &cmd)
{
	int error;
	char *errstring = NULL;
	error = luaL_loadbuffer(L, cmd.c_str(), cmd.length(), "line")
		|| lua_pcall(L, 0, 0, 0);
	if (error) {
		errstring = strdup(lua_tostring(L, -1));
		lua_pop(L, 1);
	}

	return errstring;
}

int Filter::io_read_pre(uint16_t port, int size)
{
	int ret = 0, result;

	lua_getglobal(L, "SerialICE_io_read_filter");
	lua_pushinteger(L, port);   // port
	lua_pushinteger(L, size);   // datasize

	result = lua_pcall(L, 2, 2, 0);
	if (result) {
		fprintf(stderr, "Failed to run function SerialICE_io_read_filter: %s\n",
				lua_tostring(L, -1));
		exit(1);
	}

	ret |= lua_toboolean(L, -1) ? READ_FROM_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? READ_FROM_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

int Filter::io_write_pre(uint64_t * data, uint16_t port, int size)
{
	int ret = 0, result;

	lua_getglobal(L, "SerialICE_io_write_filter");
	lua_pushinteger(L, port);   // port
	lua_pushinteger(L, size);   // datasize
	lua_pushinteger(L, *data);  // data

	result = lua_pcall(L, 3, 3, 0);
	if (result) {
		fprintf(stderr,
				"Failed to run function SerialICE_io_write_filter: %s\n",
				lua_tostring(L, -1));
		exit(1);
	}

	*data = lua_tointeger(L, -1);
	ret |= lua_toboolean(L, -2) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -3) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 3);
	return ret;
}

int Filter::load_pre(uint32_t addr, int size)
{
	int ret = 0, result;

	lua_getglobal(L, "SerialICE_memory_read_filter");
	lua_pushinteger(L, addr);
	lua_pushinteger(L, size);

	result = lua_pcall(L, 2, 2, 0);
	if (result) {
		fprintf(stderr,
				"Failed to run function SerialICE_memory_read_filter: %s\n",
				lua_tostring(L, -1));
		exit(1);
	}

	ret |= lua_toboolean(L, -1) ? READ_FROM_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? READ_FROM_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

int Filter::store_pre(uint32_t addr, int size,
										 uint64_t * data)
{
	int ret = 0, result;

	lua_getglobal(L, "SerialICE_memory_write_filter");
	lua_pushinteger(L, addr);   // address
	lua_pushinteger(L, size);   // datasize
	lua_pushinteger(L, *data);  // data

	result = lua_pcall(L, 3, 3, 0);
	if (result) {
		fprintf(stderr,
				"Failed to run function SerialICE_memory_write_filter: %s\n",
				lua_tostring(L, -1));
		exit(1);
	}

	*data = lua_tointeger(L, -1);
	ret |= lua_toboolean(L, -2) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -3) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 3);
	return ret;
}

int Filter::wrmsr_pre(uint32_t addr, uint32_t * hi, uint32_t * lo)
{
	int ret = 0, result;

	lua_getglobal(L, "SerialICE_msr_write_filter");
	lua_pushinteger(L, addr);   // port
	lua_pushinteger(L, *hi);    // high
	lua_pushinteger(L, *lo);    // low

	result = lua_pcall(L, 3, 4, 0);
	if (result) {
		fprintf(stderr,
				"Failed to run function SerialICE_msr_write_filter: %s\n", lua_tostring(L, -1));
		exit(1);
	}

	*lo = lua_tointeger(L, -1);
	*hi = lua_tointeger(L, -2);
	ret |= lua_toboolean(L, -3) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -4) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 4);
	return ret;
}

int Filter::rdmsr_pre(uint32_t addr)
{
	int ret = 0, result;

	lua_getglobal(L, "SerialICE_msr_read_filter");
	lua_pushinteger(L, addr);

	result = lua_pcall(L, 1, 2, 0);
	if (result) {
		fprintf(stderr,
				"Failed to run function SerialICE_msr_read_filter: %s\n", lua_tostring(L, -1));
		exit(1);
	}

	ret |= lua_toboolean(L, -1) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

int Filter::cpuid_pre(uint32_t eax, uint32_t ecx)
{
	int ret = 0, result;

	lua_getglobal(L, "SerialICE_cpuid_filter");
	lua_pushinteger(L, eax);    // eax before calling
	lua_pushinteger(L, ecx);    // ecx before calling

	result = lua_pcall(L, 2, 2, 0);
	if (result) {
		fprintf(stderr,
				"Failed to run function SerialICE_cpuid_filter: %s\n",
				lua_tostring(L, -1));
		exit(1);
	}

	ret |= lua_toboolean(L, -1) ? WRITE_TO_QEMU : 0;
	ret |= lua_toboolean(L, -2) ? WRITE_TO_SERIALICE : 0;
	lua_pop(L, 2);
	return ret;
}

/* SerialICE output loggers */

void Filter::read_post(int flags, uint64_t *data)
{
	int result;

	if (flags & LOG_MEMORY) {
		lua_getglobal(L, "SerialICE_memory_read_log");
	} else if (flags & LOG_IO) {
		lua_getglobal(L, "SerialICE_io_read_log");
	} else {
		fprintf(stderr, "serialice_read_log: bad type\n");
		exit(1);
	}

	lua_pushinteger(L, *data);
	result = lua_pcall(L, 1, 1, 0);
	if (result) {
		fprintf(stderr, "Failed to run function SerialICE_%s_read_log: %s\n",
				(flags & LOG_MEMORY) ? "memory" : "io", lua_tostring(L, -1));
		exit(1);
	}
	*data = lua_tointeger(L, -1);
	lua_pop(L, 1);
}

void Filter::write_post(int flags)
{
	int result;

	if (flags & LOG_MEMORY) {
		lua_getglobal(L, "SerialICE_memory_write_log");
	} else if (flags & LOG_IO) {
		lua_getglobal(L, "SerialICE_io_write_log");
	} else if (flags & LOG_MSR) {
		lua_getglobal(L, "SerialICE_msr_write_log");
	} else {
		fprintf(stderr, "serialice_write_log: bad type\n");
		exit(1);
	}

	result = lua_pcall(L, 0, 0, 0);
	if (result) {
		fprintf(stderr, "Failed to run function SerialICE_%s_write_log: %s\n",
				(flags & LOG_MEMORY) ? "memory" : "io", lua_tostring(L, -1));
		exit(1);
	}
}

void Filter::load_post(uint64_t *data)
{
	read_post(LOG_MEMORY, data);
}

void Filter::store_post(void)
{
	write_post(LOG_MEMORY);
}

void Filter::io_read_post(uint64_t *data)
{
	read_post(LOG_IO, data);
}

void Filter::io_write_post(void)
{
	write_post(LOG_IO);
}

void Filter::wrmsr_post(void)
{
	write_post(LOG_MSR);
}

void Filter::rdmsr_post(uint32_t *hi, uint32_t *lo)
{
	int result;

	lua_getglobal(L, "SerialICE_msr_read_log");
	lua_pushinteger(L, *hi);
	lua_pushinteger(L, *lo);

	result = lua_pcall(L, 2, 2, 0);
	if (result) {
		fprintf(stderr, "Failed to run function SerialICE_msr_read_log: %s\n",
			lua_tostring(L, -1));
		exit(1);
	}
	*hi = lua_tointeger(L, -2);
	*lo = lua_tointeger(L, -1);
	lua_pop(L, 2);
}

void Filter::cpuid_post(cpuid_regs_t * res)
{
	int result;

	lua_getglobal(L, "SerialICE_cpuid_log");
	lua_pushinteger(L, res->eax);        // output: eax
	lua_pushinteger(L, res->ebx);        // output: ebx
	lua_pushinteger(L, res->ecx);        // output: ecx
	lua_pushinteger(L, res->edx);        // output: edx

	result = lua_pcall(L, 4, 4, 0);
	if (result) {
		fprintf(stderr, "Failed to run function SerialICE_cpuid_log: %s\n",
				lua_tostring(L, -1));
		exit(1);
	}
	res->edx = lua_tointeger(L, -1);
	res->ecx = lua_tointeger(L, -2);
	res->ebx = lua_tointeger(L, -3);
	res->eax = lua_tointeger(L, -4);
	lua_pop(L, 4);
}
