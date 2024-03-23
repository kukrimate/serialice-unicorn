#!/usr/bin/python3
# Command line shell for the SerialICE binary protocol
from serialice import SerialICE
import re
import readline
import serial

ser = serial.Serial("/dev/ttyUSB0", 115200, exclusive=True, timeout=None)
dev = SerialICE(ser)
dev.handshake()

while True:
    line = input("> ")
    args = re.split(r"\s+", line)
    args = map(lambda x: x.strip(), args)

    cmd = next(args)
    if cmd == "rm8":
        in_addr = int(next(args), 0)
        print(f"{dev.read_mem(in_addr, 1):02x}")
    elif cmd == "rm16":
        in_addr = int(next(args), 0)
        print(f"{dev.read_mem(in_addr, 2):04x}")
    elif cmd == "rm32":
        in_addr = int(next(args), 0)
        print(f"{dev.read_mem(in_addr, 4):08x}")
    elif cmd == "rm64":
        in_addr = int(next(args), 0)
        print(f"{dev.read_mem(in_addr, 8):016x}")
    elif cmd == "wm8":
        in_addr = int(next(args), 0)
        in_val = int(next(args), 0)
        dev.write_mem(in_addr, 1, in_val)
    elif cmd == "wm16":
        in_addr = int(next(args), 0)
        in_val = int(next(args), 0)
        dev.write_mem(in_addr, 2, in_val)
    elif cmd == "wm32":
        in_addr = int(next(args), 0)
        in_val = int(next(args), 0)
        dev.write_mem(in_addr, 4, in_val)
    elif cmd == "wm64":
        in_addr = int(next(args), 0)
        in_val = int(next(args), 0)
        dev.write_mem(in_addr, 8, in_val)
    elif cmd == "rdmsr":
        in_ecx = int(next(args), 0)
        eax, edx = dev.rdmsr(in_ecx)
        print(f"EAX {eax:08x} EDX {edx:08x}")
    elif cmd == "wrmsr":
        in_ecx = int(next(args), 0)
        in_eax = int(next(args), 0)
        in_edx = int(next(args), 0)
        dev.wrmsr(in_ecx, in_eax, in_edx)
    elif cmd == "cpuid":
        in_eax = int(next(args), 0)
        in_ecx = int(next(args), 0)
        eax, ebx, ecx, edx = dev.cpuid(in_eax, in_ecx)
        print(f"EAX {eax:08x} EBX {ebx:08x} ECX {ecx:08x} EDX {edx:08x}")
    else:
        print(f"Invalid command `{line}`")
