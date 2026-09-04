#!/usr/bin/env python3
# Arbitrary-precision oracle for test_arith.cpp output.
import sys

M256 = (1 << 256) - 1
M512 = (1 << 512) - 1
fails = 0
n = 0

def set_compact(nCompact):
    size = nCompact >> 24
    word = nCompact & 0x007fffff
    if size <= 3:
        word >>= 8 * (3 - size)
        val = word
    else:
        val = word << (8 * (size - 3))
    neg = (word != 0) and (nCompact & 0x00800000) != 0
    over = (word != 0) and (size > 34 or (word > 0xff and size > 33) or (word > 0xffff and size > 32))
    return val, neg, over

def get_compact(val, fNegative=False):
    size = (val.bit_length() + 7) // 8
    if size <= 3:
        compact = (val & ((1 << 64) - 1)) << (8 * (3 - size))
    else:
        compact = (val >> (8 * (size - 3))) & ((1 << 64) - 1)
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    compact |= size << 24
    if fNegative and (compact & 0x007fffff):
        compact |= 0x00800000
    return compact & 0xffffffff

for line in sys.stdin:
    p = line.split()
    if not p:
        continue
    k = p[0]
    n += 1
    if k == "MUL":
        a, b, r = int(p[1], 16), int(p[2], 16), int(p[3], 16)
        want = (a * b) & M256
        if want != r:
            print("MUL mismatch", hex(a), hex(b), "want", hex(want), "got", hex(r)); fails += 1
    elif k == "MULW":
        a, b, r = int(p[1], 16), int(p[2], 16), int(p[3], 16)
        want = (a * b) & M512
        if want != r:
            print("MULW mismatch", hex(a), hex(b), "want", hex(want), "got", hex(r)); fails += 1
    elif k == "DIV":
        a, b, r = int(p[1], 16), int(p[2], 16), int(p[3], 16)
        want = a // b
        if want != r:
            print("DIV mismatch", hex(a), hex(b), "want", hex(want), "got", hex(r)); fails += 1
    elif k == "SETCOMPACT":
        nbits = int(p[1], 16)
        val, neg, over = set_compact(nbits)
        gotval = int(p[2], 16)
        gotneg, gotover = int(p[3]), int(p[4])
        if gotover != int(over):
            print("SETCOMPACT overflow flag", hex(nbits), "want", over, "got", gotover); fails += 1
        elif not over and (val & M256) != gotval:
            print("SETCOMPACT value", hex(nbits), "want", hex(val & M256), "got", hex(gotval)); fails += 1
        if gotneg != int(neg):
            print("SETCOMPACT neg flag", hex(nbits), "want", neg, "got", gotneg); fails += 1
    elif k == "GETCOMPACT":
        val = int(p[1], 16)
        got = int(p[2], 16)
        want = get_compact(val, False)
        if want != got:
            print("GETCOMPACT", hex(val), "want", hex(want), "got", hex(got)); fails += 1
    elif k == "RETARGET":
        tgt, m, d, r = int(p[1], 16), int(p[2]), int(p[3]), int(p[4], 16)
        want = ((tgt * m) // d) & M256
        if want != r:
            print("RETARGET mismatch tgt", hex(tgt), "m", m, "d", d, "want", hex(want), "got", hex(r)); fails += 1
    elif k == "TRUST":
        tgt, pos, pw = int(p[1], 16), int(p[2], 16), int(p[3], 16)
        want_pos = ((1 << 256) // (tgt + 1)) & M256
        want_pw = (((M256 >> 8) + 1 - 1) // (tgt + 1))  # powLimit = ~0 >> 8
        want_pw = ((M256 >> 8) // (tgt + 1))
        if want_pos != pos:
            print("TRUST pos", hex(tgt), "want", hex(want_pos), "got", hex(pos)); fails += 1
        if want_pw != pw:
            print("TRUST pow", hex(tgt), "want", hex(want_pw), "got", hex(pw)); fails += 1

print(f"checked {n} vectors, {fails} failures")
sys.exit(1 if fails else 0)
