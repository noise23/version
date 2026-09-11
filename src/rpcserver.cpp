// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013-2024 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcserver.h"

#include "alert.h"
#include "init.h"
#include "util.h"
#include "sync.h"
#include "checkpoints.h"
#include "ui_interface.h"
#include "base58.h"
#include "db.h"

#undef printf
#include <list>

#define printf OutputDebugStringF

using namespace std;
using namespace boost;

//static inline unsigned short GetDefaultRPCPort()
//{
    //return GetBoolArg("-testnet", false) ? 9909 : 9908;
//}

void RPCTypeCheck(const UniValue& params,
                  const list<UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    for (UniValue::VType t : typesExpected)
    {
        if (params.size() <= i)
            break;

        const UniValue& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == UniValue::VNULL))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   uvTypeName(t), uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}
void RPCTypeCheck(const UniValue& o,
                  const map<string, UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    for (const auto& t : typesExpected)
    {
        const UniValue& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == UniValue::VNULL)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first.c_str()));

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == UniValue::VNULL))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   uvTypeName(t.second), t.first.c_str(), uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

int64_t AmountFromValue(const UniValue& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > MAX_MONEY)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    int64_t nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

UniValue ValueFromAmount(int64_t amount)
{
    return (double)amount / (double)COIN;
}

std::string HexBits(unsigned int nBits)
{
    union {
        int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

///
/// Note: This interface may still be subject to change.
///

string CRPCTable::help(string strCommand) const
{
    string strRet;
    set<rpcfn_type> setDone;
    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
    {
        const CRPCCommand *pcmd = mi->second;
        string strMethod = mi->first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        if (pcmd->reqWallet && !pwalletMain)
            continue;
        try
        {
            UniValue params(UniValue::VARR);
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

UniValue help(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "help [command]\n"
            "List commands, or get help for a command.");

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    return tableRPC.help(strCommand);
}

UniValue stop(const UniValue& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach´ boolean argument
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "stop\n"
            "Stop Version server.");
    // Shutdown will take long enough that the response should get back
    StartShutdown();
    return "Version server stopping";
}

//
// Call Table
//

static const CRPCCommand vRPCCommands[] =
{ //  name                      function                 safe mode?  unlocked reqWallet
  //  ------------------------  -----------------------  ----------  -------- ---------
    { "help",                   &help,                   true,       true,    false },
    { "stop",                   &stop,                   true,       true,    false },
    { "getblockcount",          &getblockcount,          true,       false,   false },
    { "getconnectioncount",     &getconnectioncount,     true,       false,   false },
    { "getpeerinfo",            &getpeerinfo,            true,       false,   false },
    { "ping",                   &ping,                   true,       false,   false },
    { "getdifficulty",          &getdifficulty,          true,       false,   false },
    { "getgenerate",            &getgenerate,            true,       false,   false },
    { "setgenerate",            &setgenerate,            true,       false,   true },
    { "gethashespersec",        &gethashespersec,        true,       false,   false },
    { "getinfo",                &getinfo,                true,       false,   false },
    { "getmininginfo",          &getmininginfo,          true,       false,   false },
    { "getnewaddress",          &getnewaddress,          true,       false,   true },
    { "getaccountaddress",      &getaccountaddress,      true,       false,   true },
    { "setaccount",             &setaccount,             true,       false,   true },
    { "getaccount",             &getaccount,             false,      false,   true },
    { "getaddressesbyaccount",  &getaddressesbyaccount,  true,       false,   true },
    { "sendtoaddress",          &sendtoaddress,          false,      false,   true },
    { "getreceivedbyaddress",   &getreceivedbyaddress,   false,      false,   true },
    { "getreceivedbyaccount",   &getreceivedbyaccount,   false,      false,   true },
    { "listreceivedbyaddress",  &listreceivedbyaddress,  false,      false,   true },
    { "listreceivedbyaccount",  &listreceivedbyaccount,  false,      false,   true },
    { "backupwallet",           &backupwallet,           true,       false,   true },
    { "keypoolrefill",          &keypoolrefill,          true,       false,   true },
    { "walletpassphrase",       &walletpassphrase,       true,       false,   true },
    { "walletpassphrasechange", &walletpassphrasechange, false,      false,   true },
    { "walletlock",             &walletlock,             true,       false,   true },
    { "encryptwallet",          &encryptwallet,          false,      false,   true },
    { "validateaddress",        &validateaddress,        true,       false,   false },
    { "getbalance",             &getbalance,             false,      false,   true },
    { "move",                   &movecmd,                false,      false,   true },
    { "sendfrom",               &sendfrom,               false,      false,   true },
    { "sendmany",               &sendmany,               false,      false,   true },
    { "addmultisigaddress",     &addmultisigaddress,     false,      false,   true },
    { "getrawmempool",          &getrawmempool,          true,       false,   false },
    { "getblock",               &getblock,               false,      false,   false },
    { "getblockbynumber",       &getblockbynumber,       false,      false,   false },
    { "getblockhash",           &getblockhash,           false,      false,   false },
    { "gettransaction",         &gettransaction,         false,      false,   false }, //TODO
    { "listtransactions",       &listtransactions,       false,      false,   true },
    { "listaddressgroupings",   &listaddressgroupings,   false,      false,   true },
    { "signmessage",            &signmessage,            false,      false,   true },
    { "verifymessage",          &verifymessage,          false,      false,   false },
    { "listaccounts",           &listaccounts,           false,      false,   true },
    { "settxfee",               &settxfee,               false,      false,   true },
    // getblocktemplate reserves a coinbase key from the wallet's key pool and
    // submitblock signs the PoS block with the wallet's key, so both genuinely
    // need a loaded wallet in this codebase's implementation (unlike upstream
    // Bitcoin's later wallet-agnostic GBT); reqWallet=true routes -disablewallet
    // callers to a clean RPC error instead of a NULL-pwalletMain crash.
    { "getblocktemplate",       &getblocktemplate,       true,       false,   true },
    { "submitblock",            &submitblock,            false,      false,   true },
    { "listsinceblock",         &listsinceblock,         false,      false,   true },
    { "dumpprivkey",            &dumpprivkey,            false,      false,   true },
    { "dumpwallet",             &dumpwallet,             true,       false,   true },
    { "importprivkey",          &importprivkey,          false,      false,   true },
    { "importwallet",           &importwallet,           false,      false,   true },
    { "listunspent",            &listunspent,            false,      false,   true },
    { "getrawtransaction",      &getrawtransaction,      false,      false,   false },
    { "createrawtransaction",   &createrawtransaction,   false,      false,   false },
    { "decoderawtransaction",   &decoderawtransaction,   false,      false,   false },
    { "signrawtransaction",     &signrawtransaction,     false,      false,   false },
    { "sendrawtransaction",     &sendrawtransaction,     false,      false,   false },
    { "getcheckpoint",          &getcheckpoint,          true,       false,   false },
    { "reservebalance",         &reservebalance,         false,      true,    true },
    { "checkwallet",            &checkwallet,            false,      true,    true },
    { "repairwallet",           &repairwallet,           false,      true,    true },
    { "resendtx",               &resendtx,               false,      true,    true },
    { "makekeypair",            &makekeypair,            false,      true,    false },
    { "sendalert",              &sendalert,              false,      false,   false },
    { "getstaking",             &getstaking,             true,       false,   true },
    { "setstaking",             &setstaking,             true,       false,   true },
};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

void JSONRequest::parse(const UniValue& valRequest)
        {
            // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
            const UniValue& request = valRequest.get_obj();

            // Parse id now so errors from here on will have the id
            id = find_value(request, "id");

            // Parse method
            UniValue valMethod = find_value(request, "method");
            if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
            if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
            if (strMethod != "getblocktemplate")
                printf("ThreadRPCServer method=%s\n", strMethod.c_str());

            // Parse params
            UniValue valParams = find_value(request, "params");
            if (valParams.isArray())
                params = valParams.get_array();
            else if (valParams.isNull())
                params = UniValue(UniValue::VARR);
            else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static UniValue JSONRPCExecOne(const UniValue& req)
{
    UniValue rpc_result;

    JSONRequest jreq;
    try {
        jreq.parse(req);

        UniValue result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id);
        }
        catch (UniValue& objError)
        {
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id);
    }
    catch (std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}


string JSONRPCExecBatch(const UniValue& vReq)
{
    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return ret.write() + "\n";
}

UniValue CRPCTable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");
    if (pcmd->reqWallet && !pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (wallet disabled)");

    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode") &&
        !pcmd->okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);

    try
    {
        // Execute
        UniValue result;
        {
            if (pcmd->unlocked)
                result = pcmd->actor(params, false);
            else if (!pwalletMain) {
                LOCK(cs_main);
                result = pcmd->actor(params, false);
            } else {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                result = pcmd->actor(params, false);
            }
        }
        return result;
    }
    catch (std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}

const CRPCTable tableRPC;
