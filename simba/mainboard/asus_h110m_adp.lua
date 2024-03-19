-- SPDX-License-Identifier: GPL-2.0-or-later

function mainboard_io_pre(f, action)
	if action.addr == 0x2e or action.addr == 0x2f then
		return true
	end
	if action.addr == 0x1808 then
		action.value = 1
		return false
	end
	-- Check if the last 16-bit POST code tells us the RAM controller is ready
	if action.write and action.addr == 0x80 and action.data == 0xdd5d then
		if not ram_enabled() then
			enable_ram()
		end
	end
	return false
end

filter_mainboard_io = {
	name = "ASUS H110M-ADP",
	pre  = mainboard_io_pre,
	hide = hide_mainboard_io,
	base = 0x0,
	size = 0x10000
}

function do_mainboard_setup()
	do_default_setup()

	enable_hook(cpumsr_hooks, filter_mtrr)
	enable_hook(cpumsr_hooks, filter_intel_microcode)
	enable_hook(cpuid_hooks, filter_multiprocessor)
	enable_hook(cpuid_hooks, filter_feature_smx)

	enable_hook(io_hooks, filter_mainboard_io)

	new_car_region(0xfef00000, 0x80000)
end
