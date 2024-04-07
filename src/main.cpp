/*
 * main.cpp: Command line handling
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <getopt.h>
#include <setjmp.h>
#include <signal.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <stdexcept>

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

static jmp_buf jbuf;

static void segfault(int s)
{
	printf("SIGSEGV\n");
	longjmp(jbuf, 1);
}

static void sigint(int s)
{
	printf("SIGINT\n");
	longjmp(jbuf, 1);
}

int main(int argc, char **argv)
{
	signal(SIGSEGV, segfault);
	signal(SIGINT, sigint);

	static const struct option longopts[] = {
		{ "cpu",      required_argument, 0, 'c' }, // CPU type
		{ "firmware", required_argument, 0, 'f' }, // Firmware image
		{ "simba",    required_argument, 0, 'S' }, // Simba script
		{ "serial",   required_argument, 0, 's' }, // Serial port
		{ "help",     no_argument,       0, 'h' }, // Show help
	};

	std::optional<uc_cpu_x86>  opt_cpu = UC_CPU_X86_QEMU64;
	std::optional<const char *> opt_firmware;
	std::optional<const char *> opt_simba;
	std::optional<const char *> opt_serial;
	bool                        show_help = false;

	for (int c, longind; (c = getopt_long(argc, argv, "c:f:S:s:lh", longopts, &longind)) != -1; )
		switch (c) {
		case 'c':
			if (!(opt_cpu = str2uc_cpu_x86(optarg)))
				fprintf(stderr, "Invalid CPU type %s\n", optarg);
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
		fprintf(stderr, "Usage %s OPTIONS\n\n"
		                "Options:\n"
		                "  -c, --cpu [CPU_TYPE]            CPU type\n"
		                "  -f, --firmware [FIRMWARE_PATH]  Firmware binary\n"
		                "  -S, --simba [SIMBA_PATH]        Simba script\n"
		                "  -s, --serial [SERIAL_PATH]      Serial port\n"
		                "  -h, --help                      Show help\n",
		                argv[0]);
		return EXIT_FAILURE;
	}

	// Read ROM
	auto rom = read_file(*opt_firmware);

	// Setup target
	printf("Waiting for handshake with target...\n");
	Target target(*opt_serial);
	// auto version = target.version();
	// printf("Version: %s\n", version.c_str());
	// auto mainboard = target.mainboard();
	// printf("Mainboard: %s\n", mainboard.c_str());
	// target.enable_binary();
	std::string mainboard = "ASUS H110M-ADP";

	// Setup filter
	Filter filter(*opt_simba, mainboard.c_str(), rom.size());

	// Setup emulator
	Emulator emulator(*opt_cpu, target, filter);
	filter.init_with_emulator(emulator);

	// Map ROM into emulator
	emulator.map_rom(rom.data(), 4ULL * GiB - rom.size(), rom.size());
	// auto low_map_size = std::min<size_t>(rom.size(), 128 * KiB);
	// emulator.map_rom(rom.data(), 1 * MiB - low_map_size, low_map_size);


	int err = EXIT_SUCCESS;

	// Run emulation
	try {
		if (setjmp(jbuf)) {
			err = EXIT_FAILURE;
		} else {
			emulator.start();
		}
	} catch (const std::exception &ex) {
		printf("Caught exception during emulation: %s\n", ex.what());
		err = EXIT_FAILURE;
	}

	emulator.dump_state();
	fflush(stdout);
	return err;
}
