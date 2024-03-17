/*
 * main.cpp: Command line handling
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <getopt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include <unicorn/unicorn.h>

#include "com.h"
#include "emu.h"
#include "filter.h"
#include "misc.h"

static std::optional<uc_cpu_x86> str2uc_cpu_x86(const char *s)
{
	if (strcasecmp(s, "qemu64") == 0) return UC_CPU_X86_QEMU64;
	if (strcasecmp(s, "phenom") == 0) return UC_CPU_X86_PHENOM;
	if (strcasecmp(s, "core2duo") == 0) return UC_CPU_X86_CORE2DUO;
	if (strcasecmp(s, "kvm64") == 0) return UC_CPU_X86_KVM64;
	if (strcasecmp(s, "qemu32") == 0) return UC_CPU_X86_QEMU32;
	if (strcasecmp(s, "kvm32") == 0) return UC_CPU_X86_KVM32;
	if (strcasecmp(s, "coreduo") == 0) return UC_CPU_X86_COREDUO;
	if (strcasecmp(s, "486") == 0) return UC_CPU_X86_486;
	if (strcasecmp(s, "pentium") == 0) return UC_CPU_X86_PENTIUM;
	if (strcasecmp(s, "pentium2") == 0) return UC_CPU_X86_PENTIUM2;
	if (strcasecmp(s, "pentium3") == 0) return UC_CPU_X86_PENTIUM3;
	if (strcasecmp(s, "athlon") == 0) return UC_CPU_X86_ATHLON;
	if (strcasecmp(s, "n270") == 0) return UC_CPU_X86_N270;
	if (strcasecmp(s, "conroe") == 0) return UC_CPU_X86_CONROE;
	if (strcasecmp(s, "penryn") == 0) return UC_CPU_X86_PENRYN;
	if (strcasecmp(s, "nehalem") == 0) return UC_CPU_X86_NEHALEM;
	if (strcasecmp(s, "westmere") == 0) return UC_CPU_X86_WESTMERE;
	if (strcasecmp(s, "sandybridge") == 0) return UC_CPU_X86_SANDYBRIDGE;
	if (strcasecmp(s, "ivybridge") == 0) return UC_CPU_X86_IVYBRIDGE;
	if (strcasecmp(s, "haswell") == 0) return UC_CPU_X86_HASWELL;
	if (strcasecmp(s, "broadwell") == 0) return UC_CPU_X86_BROADWELL;
	if (strcasecmp(s, "skylake-client") == 0) return UC_CPU_X86_SKYLAKE_CLIENT;
	if (strcasecmp(s, "skylake-server") == 0) return UC_CPU_X86_SKYLAKE_SERVER;
	if (strcasecmp(s, "cascadelake-server") == 0) return UC_CPU_X86_CASCADELAKE_SERVER;
	if (strcasecmp(s, "cooperlake") == 0) return UC_CPU_X86_COOPERLAKE;
	if (strcasecmp(s, "icelake-client") == 0) return UC_CPU_X86_ICELAKE_CLIENT;
	if (strcasecmp(s, "icelake-server") == 0) return UC_CPU_X86_ICELAKE_SERVER;
	if (strcasecmp(s, "denverton") == 0) return UC_CPU_X86_DENVERTON;
	if (strcasecmp(s, "snowridge") == 0) return UC_CPU_X86_SNOWRIDGE;
	if (strcasecmp(s, "knightsmill") == 0) return UC_CPU_X86_KNIGHTSMILL;
	if (strcasecmp(s, "opteron-g1") == 0) return UC_CPU_X86_OPTERON_G1;
	if (strcasecmp(s, "opteron-g2") == 0) return UC_CPU_X86_OPTERON_G2;
	if (strcasecmp(s, "opteron-g3") == 0) return UC_CPU_X86_OPTERON_G3;
	if (strcasecmp(s, "opteron-g4") == 0) return UC_CPU_X86_OPTERON_G4;
	if (strcasecmp(s, "opteron-g5") == 0) return UC_CPU_X86_OPTERON_G5;
	if (strcasecmp(s, "epyc") == 0) return UC_CPU_X86_EPYC;
	if (strcasecmp(s, "dhyana") == 0) return UC_CPU_X86_DHYANA;
	if (strcasecmp(s, "epyc-rome") == 0) return UC_CPU_X86_EPYC_ROME;
	return {};
}

int main(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "cpu",      required_argument, 0, 'c' }, // CPU type
		{ "firmware", required_argument, 0, 'f' }, // Firmware image
		{ "simba",    required_argument, 0, 'S' }, // Simba script
		{ "serial",   required_argument, 0, 's' }, // Serial port
		{ "help",     no_argument,       0, 'h' }, // Show help
	};

	std::optional<uc_cpu_x86>  opt_cpu = UC_CPU_X86_QEMU64;
	std::optional<std::string> opt_firmware;
	std::optional<std::string> opt_simba;
	std::optional<std::string> opt_serial;
	bool                       show_help = false;

	for (int c, longind; (c = getopt_long(argc, argv, "c:f:S:s:lh", longopts, &longind)) != -1; )
		switch (c) {
		case 'c':
			if (!(opt_cpu = str2uc_cpu_x86(optarg)))
				std::cerr << "Invalid CPU type " << optarg << std::endl;
			break;
		case 'f':
			opt_firmware = optarg;
			break;
		case 'S':
			opt_simba = optarg;
			break;
		case 's':
			opt_serial = optarg;
			break;
		default:
			show_help = true;
			break;
		}

	if (!opt_cpu || !opt_firmware || !opt_simba || !opt_serial || show_help) {
		std::cerr << "Usage: " << argv[0] << " OPTIONS" << std::endl
			  << std::endl
		          << "Options:" << std::endl
		          << "  -c, --cpu [CPU_TYPE]            CPU type" << std::endl
		          << "  -f, --firmware [FIRMWARE_PATH]  Firmware binary" << std::endl
		          << "  -S, --simba [SIMBA_PATH]        Simba script" << std::endl
		          << "  -s, --serial [SERIAL_PATH]      Serial port" << std::endl
 		          << "  -h, --help                      Show help" << std::endl;
		return EXIT_FAILURE;
	}

	auto firmware_path = opt_firmware.value();
	auto simba_path = opt_simba.value();
	auto serial_path = opt_serial.value();

	// Open firmware binary
	std::fstream firmware_fs;
	firmware_fs.exceptions(std::fstream::failbit | std::fstream::badbit);
	firmware_fs.open(firmware_path, std::fstream::in);

	// Read ROM
	firmware_fs.seekg(0, std::ios_base::end);
	size_t rom_size = firmware_fs.tellg();
	firmware_fs.seekg(0, std::ios_base::beg);
	std::vector<char> rom_data;
	rom_data.reserve(rom_size);
	firmware_fs.read(rom_data.data(), rom_size);

	// Setup target
	Target target(opt_serial.value().c_str());
	target.version();
	auto mainboard = target.mainboard();

	// Setup filter
	Filter filter(opt_simba.value().c_str(), mainboard.c_str(), rom_size);

	// Setup emulator
	Emulator emulator(opt_cpu.value(), target, filter);
	filter.init_with_emulator(emulator);

	// Map ROM into emulator
	emulator.map_rom(rom_data.data(), 4ULL * GiB - rom_size, rom_size);
	auto low_map_size = std::min<size_t>(rom_size, 128 * KiB);
	emulator.map_rom(rom_data.data(), 1 * MiB - low_map_size, low_map_size);

	// Run emulation
	emulator.start();

	return EXIT_SUCCESS;
}
