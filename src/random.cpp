// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2024 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "random.h"

#include "crypto/sha512.h"
#include "cleanse.h"
#ifdef WIN32
#include "compat.h" // for Windows API
#include <bcrypt.h>
#endif
#include "util.h"

#include <assert.h>
#include <limits>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

#if defined(__linux__)
#include <sys/syscall.h> // for SYS_getrandom
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/random.h> // for getentropy()
#endif

/** Number of random bytes returned by GetOSRand.
 * When changing this constant make sure to change all call sites, and make
 * sure that the underlying OS APIs for all platforms support the number.
 * (many cap out at 256 bytes).
 */
static const int NUM_OS_RANDOM_BYTES = 32;

static void RandFailure()
{
    printf("Failed to read randomness, aborting\n");
    abort();
}

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#define HAVE_HW_RAND 1
#endif

#ifdef HAVE_HW_RAND
#ifdef __GNUC__
/** CPUID leaf query, safe under -fPIC (ebx is an explicit output operand, so
 *  GCC/Clang save and restore it around the asm as needed on 32-bit x86). */
static void GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    __asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(subleaf));
}

/** Whether the CPU advertises RDRAND support (CPUID leaf 1, ECX bit 30). */
static bool RDRandSupported()
{
    static bool support = []() {
        uint32_t eax, ebx, ecx, edx;
        GetCPUID(1, 0, eax, ebx, ecx, edx);
        static const uint32_t CPUID_F1_ECX_RDRAND = 0x40000000;
        return (ecx & CPUID_F1_ECX_RDRAND) != 0;
    }();
    return support;
}

/** Read 64 bits from the CPU's hardware RNG (RDRAND), if available.
 *  Never relied on alone: this is only ever mixed in alongside the OS
 *  CSPRNG below as an additional, independent entropy source (defense in
 *  depth against a compromised or backdoored OS RNG). Bounded retry count
 *  so a misbehaving CPU can't hang startup. */
static bool GetHWRand64(uint64_t& out)
{
    if (!RDRandSupported())
        return false;
#if defined(__x86_64__) || defined(__amd64__)
    uint8_t ok = 0;
    for (int i = 0; i < 10; i++) {
        __asm__ volatile(".byte 0x48, 0x0f, 0xc7, 0xf0; setc %1" : "=a"(out), "=q"(ok)::"cc");
        if (ok) return true;
    }
#else // 32-bit x86: two 32-bit RDRAND reads combined into one 64-bit value
    uint32_t lo = 0, hi = 0;
    uint8_t ok1 = 0, ok2 = 0;
    for (int i = 0; i < 10; i++) {
        __asm__ volatile(".byte 0x0f, 0xc7, 0xf0; setc %1" : "=a"(lo), "=q"(ok1)::"cc");
        if (!ok1) continue;
        __asm__ volatile(".byte 0x0f, 0xc7, 0xf0; setc %1" : "=a"(hi), "=q"(ok2)::"cc");
        if (!ok2) continue;
        out = ((uint64_t)hi << 32) | lo;
        return true;
    }
#endif
    return false;
}
#else // non-GCC/Clang x86 compiler: no inline asm support, skip RDRAND
static bool GetHWRand64(uint64_t& out) { (void)out; return false; }
#endif
#else
static bool GetHWRand64(uint64_t& out) { (void)out; return false; }
#endif // HAVE_HW_RAND

static inline int64_t GetPerformanceCounter()
{
    int64_t nCounter = 0;
#ifdef WIN32
    QueryPerformanceCounter((LARGE_INTEGER*)&nCounter);
#else
    timeval t;
    gettimeofday(&t, NULL);
    nCounter = (int64_t)(t.tv_sec * 1000000 + t.tv_usec);
#endif
    return nCounter;
}

#ifndef WIN32
/** Fallback: read NUM_OS_RANDOM_BYTES bytes from /dev/urandom. */
static void GetDevURandom(unsigned char* ent32)
{
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        RandFailure();
    }
    int have = 0;
    do {
        ssize_t n = read(f, ent32 + have, NUM_OS_RANDOM_BYTES - have);
        if (n <= 0 || n + have > NUM_OS_RANDOM_BYTES) {
            close(f);
            RandFailure();
        }
        have += n;
    } while (have < NUM_OS_RANDOM_BYTES);
    close(f);
}
#endif

/** Get 32 bytes of system entropy, straight from the OS CSPRNG.
 *  This replaces OpenSSL's RAND_bytes(), which on every platform we support was
 *  itself seeded from exactly these sources.
 */
static void GetOSRand(unsigned char* ent32)
{
#if defined(WIN32)
    // Windows: BCryptGenRandom with the system-preferred RNG. The older
    // CryptAcquireContextW()/CryptGenRandom() pair from <wincrypt.h> is
    // deprecated by Microsoft. (Ported from Bitcoin Core 6b4bcc16.)
    const NTSTATUS STATUS_SUCCESS = 0;
    if (BCryptGenRandom(NULL, ent32, NUM_OS_RANDOM_BYTES, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        RandFailure();
    }
#elif defined(__linux__) && defined(SYS_getrandom)
    /* getrandom(2) - available since Linux 3.17. For a request this small it
     * never returns a short read once the pool is initialised. Fall back to
     * /dev/urandom only when the syscall itself is missing. */
    int have = 0;
    do {
        ssize_t n = syscall(SYS_getrandom, ent32 + have, NUM_OS_RANDOM_BYTES - have, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOSYS) {
                GetDevURandom(ent32);
                return;
            }
            RandFailure();
        }
        have += n;
    } while (have < NUM_OS_RANDOM_BYTES);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
        RandFailure();
    }
#else
    GetDevURandom(ent32);
#endif
}

void GetRandBytes(unsigned char* buf, int num)
{
    // Serve directly from the OS CSPRNG, in NUM_OS_RANDOM_BYTES chunks.
    while (num > 0) {
        unsigned char ent32[NUM_OS_RANDOM_BYTES];
        GetOSRand(ent32);
        int chunk = (num < NUM_OS_RANDOM_BYTES) ? num : NUM_OS_RANDOM_BYTES;
        memcpy(buf, ent32, chunk);
        memory_cleanse(ent32, sizeof(ent32));
        buf += chunk;
        num -= chunk;
    }
}

void GetStrongRandBytes(unsigned char* out, int num)
{
    assert(num <= 32);
    CSHA512 hasher;
    unsigned char buf[64];

    // Source 1: OS CSPRNG.
    GetOSRand(buf);
    hasher.Write(buf, NUM_OS_RANDOM_BYTES);

    // Source 2: an independent OS CSPRNG read plus a high-resolution timestamp,
    // so that a single anomalous read cannot fully determine the output.
    GetOSRand(buf);
    hasher.Write(buf, NUM_OS_RANDOM_BYTES);
    int64_t tsc = GetPerformanceCounter();
    hasher.Write((const unsigned char*)&tsc, sizeof(tsc));

    // Source 3: CPU hardware RNG (RDRAND), if the processor supports it.
    // Purely additive: if unavailable, or if the OS CSPRNG is itself
    // compromised, this is an independent line of defense rather than a
    // single point of failure.
    uint64_t hw;
    if (GetHWRand64(hw))
        hasher.Write((const unsigned char*)&hw, sizeof(hw));

    // Source 4: process id, to further separate output between processes
    // that might otherwise race to read the OS RNG at the same instant.
#ifdef WIN32
    DWORD pid = GetCurrentProcessId();
#else
    pid_t pid = getpid();
#endif
    hasher.Write((const unsigned char*)&pid, sizeof(pid));

    // Produce output.
    hasher.Finalize(buf);
    memcpy(out, buf, num);
    memory_cleanse(buf, sizeof(buf));
}

bool Random_SanityCheck()
{
    // Verify GetOSRand() actually produces (statistically) distinct,
    // non-constant output rather than e.g. silently returning zeros: fill a
    // buffer with a fixed pattern, request OS randomness NUM_OS_RANDOM_BYTES
    // times, and require that every byte position was overwritten to a
    // non-original value at least once.
    unsigned char seen[NUM_OS_RANDOM_BYTES];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < NUM_OS_RANDOM_BYTES; i++) {
        unsigned char buf[NUM_OS_RANDOM_BYTES];
        memset(buf, 0xAA, sizeof(buf));
        GetOSRand(buf);
        for (int j = 0; j < NUM_OS_RANDOM_BYTES; j++) {
            if (buf[j] != 0xAA)
                seen[j] = 1;
        }
    }
    for (int j = 0; j < NUM_OS_RANDOM_BYTES; j++) {
        if (!seen[j])
            return false;
    }

    // Verify the performance counter used to strengthen GetStrongRandBytes
    // actually advances. A busy-loop delay isn't reliable here: on a fast/idle
    // core it can complete within a single tick of the underlying (merely
    // microsecond-resolution, on non-Windows platforms) clock, making this
    // check intermittently fail. Sleep a real 1ms of wall-clock time instead.
    int64_t start = GetPerformanceCounter();
    MilliSleep(1);
    int64_t end = GetPerformanceCounter();
    if (end <= start)
        return false;

    // Verify two independent GetStrongRandBytes() calls don't collide.
    unsigned char r1[32], r2[32];
    GetStrongRandBytes(r1, 32);
    GetStrongRandBytes(r2, 32);
    if (memcmp(r1, r2, 32) == 0)
        return false;

    return true;
}

uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return (nRand % nMax);
}

int GetRandInt(int nMax)
{
    return GetRand(nMax);
}

uint256 GetRandHash()
{
    uint256 hash;
    GetRandBytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}

uint32_t insecure_rand_Rz = 11;
uint32_t insecure_rand_Rw = 11;
void seed_insecure_rand(bool fDeterministic)
{
    // The seed values have some unlikely fixed points which we avoid.
    if(fDeterministic)
    {
        insecure_rand_Rz = insecure_rand_Rw = 11;
    } else {
        uint32_t tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while(tmp == 0 || tmp == 0x9068ffffU);
        insecure_rand_Rz = tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while(tmp == 0 || tmp == 0x464fffffU);
        insecure_rand_Rw = tmp;
    }
}
