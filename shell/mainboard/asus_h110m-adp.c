/* SPDX-License-Identifier: GPL-2.0-or-later */

const char boardname[33]="ASUS H110M-ADP                  ";

static void chipset_init(void)
{
	southbridge_init();
	superio_init(0x2e);
}
