// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013-2018 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOINRPC_SERVER_H_
#define _BITCOINRPC_SERVER_H_ 1

#include "rpcprotocol.h"
#include "util.h"
#include "checkpoints.h"

#include <string>
#include <list>
#include <map>

class CReserveKey;
class CBlockIndex;

static inline unsigned short GetDefaultRPCPort()
{
  return GetBoolArg("-testnet", false) ? 9909 : 9908;
};

/** A parsed, single JSON-RPC request. */
class JSONRequest
{
public:
    UniValue id;
    std::string strMethod;
    UniValue params;

    JSONRequest() {}
    void parse(const UniValue& valRequest);
};

/** Execute a batch (array) of JSON-RPC requests, returning the serialized reply. */
std::string JSONRPCExecBatch(const UniValue& vReq);

/*
  Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
  the right number of arguments are passed, just that any passed are the correct type.
  Use like:  RPCTypeCheck(params, {str_type, int_type, obj_type});
*/
void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected, bool fAllowNull=false);
/*
  Check for expected keys/value types in an Object.
  Use like: RPCTypeCheck(object, {{"name", str_type}, {"value", int_type}});
*/
void RPCTypeCheck(const UniValue& o,
                  const std::map<std::string, UniValue::VType>& typesExpected, bool fAllowNull=false);

typedef UniValue(*rpcfn_type)(const UniValue& params, bool fHelp);

class CRPCCommand
{
public:
    std::string name;
    rpcfn_type actor;
    bool okSafeMode;
    bool unlocked;
    bool reqWallet;
};

/**
 * Bitcoin RPC command dispatcher.
 */
class CRPCTable
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands;
public:
    CRPCTable();
    const CRPCCommand* operator[](std::string name) const;
    std::string help(std::string name) const;

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */
    UniValue execute(const std::string &method, const UniValue &params) const;
};

extern const CRPCTable tableRPC;

extern int64_t nWalletUnlockTime;
extern int64_t AmountFromValue(const UniValue& value);
extern UniValue ValueFromAmount(int64_t amount);
extern double GetDifficulty(const CBlockIndex* blockindex = NULL);
extern double GetPoWMHashPS(const CBlockIndex* blockindex = NULL);
extern double GetPoSKernelPS(const CBlockIndex* blockindex = NULL);

extern std::string HexBits(unsigned int nBits);
extern std::string HelpRequiringPassphrase();
extern void EnsureWalletIsUnlocked();

extern UniValue getconnectioncount(const UniValue& params, bool fHelp); // in rpcnet.cpp
extern UniValue getpeerinfo(const UniValue& params, bool fHelp);
extern UniValue ping(const UniValue& params, bool fHelp);
extern UniValue sendalert(const UniValue& params, bool fHelp);
extern UniValue dumpprivkey(const UniValue& params, bool fHelp); // in rpcdump.cpp
extern UniValue dumpwallet(const UniValue& params, bool fHelp);
extern UniValue importprivkey(const UniValue& params, bool fHelp);
extern UniValue importwallet(const UniValue& params, bool fHelp);

extern UniValue getgenerate(const UniValue& params, bool fHelp); // in rpcmining.cpp
extern UniValue setgenerate(const UniValue& params, bool fHelp);
extern UniValue gethashespersec(const UniValue& params, bool fHelp);
extern UniValue getmininginfo(const UniValue& params, bool fHelp);
extern UniValue getstaking(const UniValue& params, bool fHelp);
extern UniValue setstaking(const UniValue& params, bool fHelp);

extern UniValue getblocktemplate(const UniValue& params, bool fHelp);
extern UniValue submitblock(const UniValue& params, bool fHelp);

extern UniValue getnewaddress(const UniValue& params, bool fHelp); // in rpcwallet.cpp
extern UniValue getaccountaddress(const UniValue& params, bool fHelp);
extern UniValue setaccount(const UniValue& params, bool fHelp);
extern UniValue getaccount(const UniValue& params, bool fHelp);
extern UniValue getaddressesbyaccount(const UniValue& params, bool fHelp);
extern UniValue sendtoaddress(const UniValue& params, bool fHelp);
extern UniValue signmessage(const UniValue& params, bool fHelp);
extern UniValue verifymessage(const UniValue& params, bool fHelp);
extern UniValue getreceivedbyaddress(const UniValue& params, bool fHelp);
extern UniValue getreceivedbyaccount(const UniValue& params, bool fHelp);
extern UniValue getbalance(const UniValue& params, bool fHelp);
extern UniValue movecmd(const UniValue& params, bool fHelp);
extern UniValue sendfrom(const UniValue& params, bool fHelp);
extern UniValue sendmany(const UniValue& params, bool fHelp);
extern UniValue addmultisigaddress(const UniValue& params, bool fHelp);
extern UniValue listreceivedbyaddress(const UniValue& params, bool fHelp);
extern UniValue listreceivedbyaccount(const UniValue& params, bool fHelp);
extern UniValue listtransactions(const UniValue& params, bool fHelp);
extern UniValue listaddressgroupings(const UniValue& params, bool fHelp);
extern UniValue listaccounts(const UniValue& params, bool fHelp);
extern UniValue listsinceblock(const UniValue& params, bool fHelp);
extern UniValue gettransaction(const UniValue& params, bool fHelp);
extern UniValue backupwallet(const UniValue& params, bool fHelp);
extern UniValue keypoolrefill(const UniValue& params, bool fHelp);
extern UniValue walletpassphrase(const UniValue& params, bool fHelp);
extern UniValue walletpassphrasechange(const UniValue& params, bool fHelp);
extern UniValue walletlock(const UniValue& params, bool fHelp);
extern UniValue encryptwallet(const UniValue& params, bool fHelp);
extern UniValue validateaddress(const UniValue& params, bool fHelp);
extern UniValue getinfo(const UniValue& params, bool fHelp);
extern UniValue reservebalance(const UniValue& params, bool fHelp);
extern UniValue checkwallet(const UniValue& params, bool fHelp);
extern UniValue repairwallet(const UniValue& params, bool fHelp);
extern UniValue resendtx(const UniValue& params, bool fHelp);
extern UniValue makekeypair(const UniValue& params, bool fHelp);

extern UniValue getrawtransaction(const UniValue& params, bool fHelp); // in rcprawtransaction.cpp
extern UniValue listunspent(const UniValue& params, bool fHelp);
extern UniValue createrawtransaction(const UniValue& params, bool fHelp);
extern UniValue decoderawtransaction(const UniValue& params, bool fHelp);
extern UniValue signrawtransaction(const UniValue& params, bool fHelp);
extern UniValue sendrawtransaction(const UniValue& params, bool fHelp);

extern UniValue getblockcount(const UniValue& params, bool fHelp); // in rpcblockchain.cpp
extern UniValue getdifficulty(const UniValue& params, bool fHelp);
extern UniValue settxfee(const UniValue& params, bool fHelp);
extern UniValue getrawmempool(const UniValue& params, bool fHelp);
extern UniValue getblockhash(const UniValue& params, bool fHelp);
extern UniValue getblock(const UniValue& params, bool fHelp);
extern UniValue getblockbynumber(const UniValue& params, bool fHelp);
extern UniValue getcheckpoint(const UniValue& params, bool fHelp);

#endif
