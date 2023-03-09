// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013-2018 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hash.h"
#include "db.h"
#include "miner.h"
#include "kernel.h"
#include <boost/algorithm/string/replace.hpp>

using namespace std;

map<unsigned int, unsigned int> mapHashedBlocks;

//////////////////////////////////////////////////////////////////////////////
//
// VersionMiner
//

string strMintMessage = "Info: Minting suspended due to locked wallet.";
string strMintWarning;

//
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
//
//???bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash) {
bool static ScanHash(const std::unique_ptr<CBlock>& pblock, uint32_t& nNonce, uint256 *phash) {
    // Write the first 76 bytes of the block header to a double-SHA256 state.
    CHash256 hasher;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock;
    assert(ss.size() == 80);
    hasher.Write((unsigned char*)&ss[0], 76);

    for (;;) {
        nNonce++;

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result.
        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint16_t*)phash)[15] == 0)
            return true;

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xffff) == 0)
            return false;
    }
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n", 
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        for (uint256 hash : setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
int64_t nLastCoinStakeSearchInterval = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

// CreateNewBlock:
//   fProofOfStake: try (best effort) to make a proof-of-stake block
CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake)
{
    // Create new block
    std::unique_ptr<CBlock> pblock(new CBlock());
    if (!pblock.get())
        return NULL;

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    if (!fProofOfStake)
    {
        CReserveKey reservekey(pwallet);
        txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;
    }
    else
        txNew.vout[0].SetEmpty();

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64_t nMinTxFee = MIN_TX_FEE;
    if (mapArgs.count("-mintxfee"))
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);

    // version: if coinstake available add coinstake tx
    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime();  // only initialized at startup
    CBlockIndex* pindexPrev = pindexBest;

    if (fProofOfStake)  // attempt to find a coinstake
    {

        pblock->nBits = GetNextTargetRequired(pindexPrev, true);
        CTransaction txCoinStake;
        int64_t nSearchTime = txCoinStake.nTime; // search to current time
        if (nSearchTime > nLastCoinStakeSearchTime)
        {
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake))
            {
                if (txCoinStake.nTime >= max(pindexPrev->GetMedianTimePast()+1, PastDrift(pindexPrev->GetBlockTime(), 0)))
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    pblock->vtx[0].nTime = txCoinStake.nTime;
                    pblock->vtx.push_back(txCoinStake);
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
    }


    pblock->nBits = GetNextTargetRequired(pindexPrev, pblock->IsProofOfStake());


    // Collect memory pool transactions into the block
    int64_t nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache view(*pcoinsTip, true);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || tx.IsCoinStake() || !tx.IsFinal())
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64_t nTotalIn = 0;
            bool fMissingInputs = false;
            for (const CTxIn& txin : tx.vin)
            {
                // Read prev transaction
                CCoins coins;
                if (!view.GetCoins(txin.prevout.hash, coins))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    continue;
                }
                int64_t nValueIn = coins.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = pindexPrev->nHeight - coins.nHeight;
                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // second layer cached modifications just for this transaction
            CCoinsViewCache viewTemp(view, true);

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Timestamp limit
            if (tx.nTime > GetAdjustedTime() || (pblock->IsProofOfStake() && tx.nTime > pblock->vtx[1].nTime))
                continue;

            // version: simplify transaction fee - allow free = false
            int64_t nMinFee = tx.GetMinFee(nBlockSize, false, GMF_BLOCK);
            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || (dPriority < COIN * 144 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!tx.CheckInputs(viewTemp, CS_ALWAYS, false))
                continue;

            int64_t nTxFees = tx.GetValueIn(viewTemp)-tx.GetValueOut();
            if (nTxFees < nMinFee)
                continue;

            nTxSigOps += tx.GetP2SHSigOpCount(viewTemp);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

/*
 * We need to call UpdateCoins using actual block timestamp, so don't perform this here.
 *
            CTxUndo txundo;
            if (!tx.UpdateCoins(viewTemp, txundo, pindexPrev->nHeight+1, pblock->nTime))
                continue;
*/

            // push changes from the second layer cache to the first one
            viewTemp.Flush();
            uint256 hash = tx.GetHash();

            // Added
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                for (COrphan* porphan : mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        if (fDebug && GetBoolArg("-printpriority"))
            printf("CreateNewBlock(): total size %" PRIu64 "\n", nBlockSize);
    }

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pindexPrev->GetBlockHash());
    
    CBlockIndex* pindexPrevious = (*mi).second;
    int nHeight = pindexPrevious->nHeight+1;
    if (pblock->IsProofOfWork())
        pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(nHeight, pblock->nBits, nFees);

    
    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    if (pblock->IsProofOfStake())
        pblock->nTime      = pblock->vtx[1].nTime; //same as coinstake timestamp
    pblock->nTime          = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
    pblock->nTime = max(pblock->GetBlockTime(), PastDrift(pindexPrev->GetBlockTime(), 0));
    if (pblock->IsProofOfWork())
        pblock->UpdateTime(pindexPrev);
    pblock->nNonce         = 0;

    return pblock.release();
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    pblock->vtx[0].vin[0].scriptSig = (CScript() << pblock->nTime << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hashblock = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if(!pblock->IsProofOfWork())
        return error("CheckWork() : %s is not a proof-of-work block", hashblock.GetHex().c_str());

    if (hashblock > hashTarget)
        return error("CheckWork() : proof-of-work not meeting target");

    //// debug print
    printf("CheckWork() : new proof-of-work block found  \n  hashblock: %s  \ntarget: %s\n", hashblock.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("%s ", DateTimeStrFormat(GetTime()).c_str());
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CheckWork : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashblock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("CheckWork : ProcessBlock, block not accepted");
    }

    return true;
}

bool CheckStake(CBlock* pblock, CWallet& wallet)
{
    uint256 proofHash = 0, hashTarget = 0;
    uint256 hashBlock = pblock->GetHash();
    bool fFatal = false;

    if(!pblock->IsProofOfStake())
        return error("CheckStake() : %s is not a proof-of-stake block", hashBlock.GetHex().c_str());

    // verify hash target and signature of coinstake tx
    if (!CheckProofOfStake(pblock->vtx[1], pblock->nBits, proofHash, hashTarget, fFatal))
        return error("CheckStake() : proof-of-stake checking failed");

    //// debug print
    printf("CheckStake() : new proof-of-stake block found \n hash: %s \nproofhash: %s \ntarget: %s\n", hashBlock.GetHex().c_str(), proofHash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("out %s\n", FormatMoney(pblock->vtx[1].GetValueOut()).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CheckStake() : generated block is stale");

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashBlock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("CheckStake() : ProcessBlock, block not accepted");
    }

    return true;
}

void static ThreadBitcoinMiner(void* parg);

static bool fGenerateBitcoins = false;
static bool fLimitProcessors = false;
static int nLimitProcessors = -1;

void BitcoinMiner(CWallet *pwallet, bool fProofOfStake)
{
    printf("CPUMiner started for proof-of-%s\n", fProofOfStake? "stake" : "work");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread("version-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    while (fGenerateBitcoins || (fProofOfStake && fStaking))
    {
        if (fShutdown)
            return;
        while (vNodes.empty() || IsInitialBlockDownload() || vNodes.size() < 2 || nBestHeight < GetNumBlocksOfPeers())
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
            if ((!fGenerateBitcoins) && !fProofOfStake)
                return;
        }

        while (pwallet->IsLocked())
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }

        if(mapHashedBlocks.count(nBestHeight)) //search our map of hashed blocks, see if bestblock has been hashed yet
        {
            if(GetTime() - mapHashedBlocks[nBestHeight] < min((int)(pwallet->nHashDrift  * 0.5), 180)) // wait half of the nHashDrift with max wait of 3 minutes
            {
                MilliSleep(2500); // 2.5 second sleep
                continue;
            }
        }

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;

        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwallet, fProofOfStake));
        if (!pblock.get())
            return;

        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

        if (fProofOfStake)
        {
            // version: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                if (!pblock->SignBlock(*pwallet))
                {
                    strMintWarning = strMintMessage;
                    continue;
                }
                strMintWarning = "";
                printf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString().c_str()); 
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                CheckStake(pblock.get(), *pwallet);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
            }
            continue;
        }

        printf("Running BitcoinMiner with %lu transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Search
        //
        int64_t nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        uint256 hash;
        uint32_t nNonce = 0;
        uint32_t nOldNonce = 0;
        while (true)
        {
            bool fFound = ScanHash(pblock, nNonce, &hash);
            uint32_t nHashesDone = nNonce - nOldNonce;
            nOldNonce = nNonce;

            // Check if something found
            if (fFound)
            {
                if (hash <= hashTarget)
                {
                    // Found a solution
                    pblock->nNonce = nNonce;
                    assert(hash == pblock->GetHash());
                    if (!pblock->SignBlock(*pwallet))
                    {
                        strMintWarning = strMintMessage;
                        break;
                    }
                    strMintWarning = "";
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock.get(), *pwallet, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    break;
                }
            }

            // Meter hashes/sec
            static int64_t nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64_t nLogTime;
                        if (GetTime() - nLogTime > 30 * 60)
                        {
                            nLogTime = GetTime();
                            printf("%s ", DateTimeStrFormat(GetTime()).c_str());
                            printf("hashmeter %3d CPUs %6.0f khash/s\n", vnThreadsRunning[THREAD_MINER], dHashesPerSec/1000.0);
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            if (fShutdown)
                return;
            if (!fGenerateBitcoins)
                return;
            if (fLimitProcessors && vnThreadsRunning[THREAD_MINER] > nLimitProcessors)
                return;
            if (vNodes.empty())
                break;
            if (nNonce >= 0xffff0000)
                break;
            if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pindexBest)
                break;

            // Update nTime every few seconds
            pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime = max(pblock->GetBlockTime(), PastDrift(pindexPrev->GetBlockTime(), 0));
            pblock->UpdateTime(pindexPrev);
//            nBlockTime = ByteReverse(pblock->nTime);
            if (pblock->GetBlockTime() >= FutureDrift((int64_t)pblock->vtx[0].nTime, 0))
                break;  // need to update coinbase timestamp
        }
    }
}

void static ThreadBitcoinMiner(void* parg)
{
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        vnThreadsRunning[THREAD_MINER]++;
        BitcoinMiner(pwallet, false);
        vnThreadsRunning[THREAD_MINER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_MINER]--;
        PrintException(&e, "ThreadBitcoinMiner()");
    } catch (...) {
        vnThreadsRunning[THREAD_MINER]--;
        PrintException(NULL, "ThreadBitcoinMiner()");
    }
    nHPSTimerStart = 0;
    if (vnThreadsRunning[THREAD_MINER] == 0)
        dHashesPerSec = 0;
    printf("ThreadBitcoinMiner exiting, %d threads remaining\n", vnThreadsRunning[THREAD_MINER]);
}


void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    fGenerateBitcoins = fGenerate;
    nLimitProcessors = GetArg("-genproclimit", -1);
    if (nLimitProcessors == 0)
        fGenerateBitcoins = false;
    fLimitProcessors = (nLimitProcessors != -1);

    if (fGenerate)
    {
        int nProcessors = boost::thread::hardware_concurrency();
        printf("%d processors\n", nProcessors);
        if (nProcessors < 1)
            nProcessors = 1;
        if (fLimitProcessors && nProcessors > nLimitProcessors)
            nProcessors = nLimitProcessors;
        int nAddThreads = nProcessors - vnThreadsRunning[THREAD_MINER];
        printf("Starting %d BitcoinMiner threads\n", nAddThreads);
        for (int i = 0; i < nAddThreads; i++)
        {
            if (!NewThread(ThreadBitcoinMiner, pwallet))
                printf("Error: NewThread(ThreadBitcoinMiner) failed\n");
            MilliSleep(10);
        }
    }
}
