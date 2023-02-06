// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2013-2018 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef VERSION_KERNEL_H
#define VERSION_KERNEL_H

#include "main.h"

// MODIFIER_INTERVAL: time to elapse before new modifier is computed
static const unsigned int MODIFIER_INTERVAL = 6 * 60 * 60; // old interval between stake modifiers is 6 hours
static const unsigned int MODIFIER_INTERVAL_V2 = 40 * 60; // new interval between stake modifiers is 40 minutes
extern unsigned int nModifierInterval;
extern unsigned int nModifierIntervalNew;

// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

// Compute the hash modifier for proof-of-stake
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier);

// Check whether stake kernel meets hash target
// Sets hashProofOfStake and targetProofOfStake on success return
bool CheckStakeKernelHash(unsigned int nBits, const CBlock& blockFrom, unsigned int nTxPrevOffset, const CTransaction& txPrev, 
const COutPoint& prevout, unsigned int nTimeTx, unsigned int nInterval, bool fCheck, uint256& hashProofOfStake, bool& fFatal, bool fPrintProofOfStake=false);
uint256 stakeHash(unsigned int nTimeTx, unsigned int nTxPrevTime, CDataStream ss, unsigned int prevoutIndex, unsigned int nTxPrevOffset, unsigned int nTimeBlockFrom);
bool stakeTargetHit(uint256 hashProofOfStake, unsigned int nAge, int64_t nValueIn, CBigNum bnTargetPerCoinDay);

// Check kernel hash target and coinstake signature
// Sets hashProofOfStake and targetProofOfStake on success return
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake, uint256& targetProofOfStake, bool& fFatal);

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx);

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex);

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum);

// Get time weight using supplied timestamps 
int64_t GetWeight(int64_t nIntervalBeginning, int64_t nIntervalEnd);

#endif // VERSION_KERNEL_H
