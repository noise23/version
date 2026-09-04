// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H

#include "uint256.h"

#include <limits>
#include <stdint.h>

/**
 * Functions to gather random data from the operating system CSPRNG
 * (getrandom(2) / getentropy() / CryptGenRandom, with a /dev/urandom fallback).
 */
void GetRandBytes(unsigned char* buf, int num);
uint64_t GetRand(uint64_t nMax);
int GetRandInt(int nMax);
uint256 GetRandHash();

/**
 * Function to gather random data from multiple sources, failing whenever any
 * of those source fail to provide a result.
 */
void GetStrongRandBytes(unsigned char* buf, int num);

/**
 * Check that OS randomness is available and functioning correctly.
 * Called once during startup; aborts the process (via RandFailure) if the
 * OS CSPRNG is silently broken (e.g. returns constant/all-zero output)
 * rather than letting the wallet mint weak keys.
 */
bool Random_SanityCheck();

/**
 * UniformRandomBitGenerator adaptor over the OS CSPRNG so it can be passed
 * to standard algorithms such as std::shuffle (which replaced the removed
 * std::random_shuffle in C++17).
 */
struct RandomBitGenerator
{
    typedef uint64_t result_type;
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
    result_type operator()()
    {
        result_type r;
        GetRandBytes(reinterpret_cast<unsigned char*>(&r), sizeof(r));
        return r;
    }
};

/**
 * Seed insecure_rand using the random pool.
 * @param Deterministic Use a determinstic seed
 */
void seed_insecure_rand(bool fDeterministic = false);

/**
 * MWC RNG of George Marsaglia
 * This is intended to be fast. It has a period of 2^59.3, though the
 * least significant 16 bits only have a period of about 2^30.1.
 *
 * @return random value
 */
extern uint32_t insecure_rand_Rz;
extern uint32_t insecure_rand_Rw;
static inline uint32_t insecure_rand(void)
{
    insecure_rand_Rz = 36969 * (insecure_rand_Rz & 65535) + (insecure_rand_Rz >> 16);
    insecure_rand_Rw = 18000 * (insecure_rand_Rw & 65535) + (insecure_rand_Rw >> 16);
    return (insecure_rand_Rw << 16) + insecure_rand_Rz;
}

#endif // BITCOIN_RANDOM_H
