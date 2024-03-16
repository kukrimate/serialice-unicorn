/*
 * main.cpp: Command line handling
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <getopt.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "serialice.h"

extern Target *g_target;
extern Filter *g_filter;
extern Emulator *g_emulator;

int main(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "firmware", required_argument, 0, 'f' }, // Firmware image
		{ "simba",    required_argument, 0, 'S' }, // Simba script
		{ "serial",   required_argument, 0, 's' }, // Serial port
		{ "help",     no_argument,       0, 'h' }, // Show help
	};

	std::optional<std::string> opt_firmware;
	std::optional<std::string> opt_simba;
	std::optional<std::string> opt_serial;
	bool                       show_help = false;

	for (int c, longind; (c = getopt_long(argc, argv, "f:S:s:lh", longopts, &longind)) != -1; )
		switch (c) {
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
			if (c != 'h')
				std::cerr << "Unrecognized option " << c << std::endl;
			show_help = true;
			break;
		}

	if (!opt_firmware.has_value() ||
	    !opt_simba.has_value() ||
	    !opt_serial.has_value() ||
	    show_help) {
		std::cerr << "Usage: " << argv[0] << " OPTIONS" << std::endl
			  << std::endl
		          << "Options:" << std::endl
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
	firmware_fs.seekg(0, std::fstream::seekdir::_S_end);
	size_t rom_size = firmware_fs.tellg();
	firmware_fs.seekg(0, std::fstream::seekdir::_S_beg);
	std::vector<char> rom_data;
	rom_data.reserve(rom_size);
	firmware_fs.read(rom_data.data(), rom_size);

	// Setup emulator
	Emulator emulator;
	g_emulator = &emulator;

	emulator.map_rom(rom_data.data(), 4ULL * GiB - rom_size, rom_size);
	auto low_map_size = std::min<size_t>(rom_size, 128 * KiB);
	emulator.map_rom(rom_data.data(), 1 * MiB - low_map_size, low_map_size);

	// Setup target
	Target target(opt_serial.value().c_str());
	g_target = &target;
	target.version();
	auto mainboard = target.mainboard();

	// Setup filter
	Filter filter(opt_simba.value().c_str(), mainboard.c_str(), rom_size);
	g_filter = &filter;

	// Run emulation
	emulator.start();

	return EXIT_SUCCESS;
}
