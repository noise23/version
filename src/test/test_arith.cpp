// Throwaway: emit test vectors for the new fixed-width uint256/uint512
// arithmetic in uint256.h so an arbitrary-precision oracle (test_arith.py)
// can confirm it matches what CBigNum used to compute. Not part of any build.
//
//   g++ -std=c++11 -O2 -I. test_arith.cpp -o /tmp/ta && /tmp/ta | python3 test_arith.py

#include <cstdio>
#include <stdint.h>

// uint256.h wants this (normally in util.cpp)
const signed char p_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

#include "uint256.h"

static uint64_t s = 88172645463325252ULL;
static uint64_t xr() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

static uint256 randU(int maxbits)
{
    uint256 r;
    unsigned char* p = r.begin();
    for (int i = 0; i < 32; i++) p[i] = (unsigned char)xr();
    r >>= (256 - (int)(xr() % (maxbits + 1)));
    return r;
}

static std::string hex512(const uint512& w)
{
    const unsigned char* p = (const unsigned char*)w.begin();
    char buf[129];
    for (int i = 0; i < 64; i++) sprintf(buf + i * 2, "%02x", p[63 - i]);
    buf[128] = 0;
    return buf;
}

int main()
{
    // Deterministic edge cases first.
    {
        uint32_t edgeBits[] = {
            0x1d00ffff, 0x1e0fffff, 0x1f00ffff, 0x1f7fffff, 0x20000001,
            0x03000000, 0x01003456, 0x02008000, 0x05009234, 0x1b0404cb,
            0xff123456, 0x21010000, 0x22000100, 0x1d008000,
        };
        for (unsigned e = 0; e < sizeof(edgeBits)/sizeof(edgeBits[0]); e++) {
            uint256 c; bool neg=false, over=false;
            c.SetCompact(edgeBits[e], &neg, &over);
            printf("SETCOMPACT %08x %s %d %d\n", edgeBits[e], c.GetHex().c_str(), (int)neg, (int)over);
            if (!over && !(c == uint256(0)))
                printf("GETCOMPACT %s %08x\n", c.GetHex().c_str(), c.GetCompact(neg));
        }
        uint256 one(1), zero(0), big; big = ~uint256(0);
        printf("MUL %s %s %s\n", big.GetHex().c_str(), one.GetHex().c_str(), (big*one).GetHex().c_str());
        printf("MUL %s %s %s\n", big.GetHex().c_str(), zero.GetHex().c_str(), (big*zero).GetHex().c_str());
        printf("MUL %s %s %s\n", big.GetHex().c_str(), big.GetHex().c_str(), (big*big).GetHex().c_str());
        printf("MULW %s %s %s\n", big.GetHex().c_str(), big.GetHex().c_str(), hex512(uint512(big)*uint512(big)).c_str());
        printf("DIV %s %s %s\n", big.GetHex().c_str(), one.GetHex().c_str(), (big/one).GetHex().c_str());
        printf("DIV %s %s %s\n", one.GetHex().c_str(), big.GetHex().c_str(), (one/big).GetHex().c_str());
        uint256 seven(7), three(3);
        printf("DIV %s %s %s\n", seven.GetHex().c_str(), three.GetHex().c_str(), (seven/three).GetHex().c_str());
    }

    for (int i = 0; i < 60000; i++) {
        uint256 a = randU(256), b = randU(256);
        printf("MUL %s %s %s\n", a.GetHex().c_str(), b.GetHex().c_str(), (a * b).GetHex().c_str());
        printf("MULW %s %s %s\n", a.GetHex().c_str(), b.GetHex().c_str(),
               hex512(uint512(a) * uint512(b)).c_str());
        if (!(b == uint256(0)))
            printf("DIV %s %s %s\n", a.GetHex().c_str(), b.GetHex().c_str(), (a / b).GetHex().c_str());

        // compact round-trips
        uint32_t nBits = ((1 + (uint32_t)(xr() % 33)) << 24) | (uint32_t)(xr() & 0x7fffff);
        uint256 c; bool neg = false, over = false;
        c.SetCompact(nBits, &neg, &over);
        printf("SETCOMPACT %08x %s %d %d\n", nBits, c.GetHex().c_str(), (int)neg, (int)over);
        if (!over && !(c == uint256(0)))
            printf("GETCOMPACT %s %08x\n", c.GetHex().c_str(), c.GetCompact(neg));

        // wide retarget: (a * m) / d  narrowed to 256
        uint256 tgt; bool o2 = false;
        tgt.SetCompact(((1 + (uint32_t)(xr() % 31)) << 24) | (uint32_t)(xr() & 0x7fffff), 0, &o2);
        if (!o2) {
            int64_t m = 1 + (int64_t)(xr() % 8000000);
            int64_t d = 1 + (int64_t)(xr() % 8000000);
            uint512 w = uint512(tgt) * uint512((uint64_t)m);
            w /= uint512((uint64_t)d);
            printf("RETARGET %s %lld %lld %s\n", tgt.GetHex().c_str(),
                   (long long)m, (long long)d, w.trim256().GetHex().c_str());

            // block trust: PoS 2^256/(t+1), PoW powLimit/(t+1)
            if (!(tgt == uint256(0))) {
                uint256 one(1);
                uint256 pos = (uint256(~tgt) / (tgt + one)) + one;
                uint256 powLimit = ~uint256(0); powLimit >>= 8;
                uint256 pw = powLimit / (tgt + one);
                printf("TRUST %s %s %s\n", tgt.GetHex().c_str(), pos.GetHex().c_str(), pw.GetHex().c_str());
            }
        }
    }
    return 0;
}
