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

    // Produce output.
    hasher.Finalize(buf);
    memcpy(out, buf, num);
    memory_cleanse(buf, sizeof(buf));
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
