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
#include <boost/bind/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <list>

#define printf OutputDebugStringF
// MinGW 3.4.5 gets "fatal error: had to relocate PCH" if the json headers are
// precompiled in headers.h.  The problem might be when the pch file goes over
// a certain size around 145MB.  If we need access to json_spirit outside this
// file, we could use the compiled json_spirit option.

using namespace std;
using namespace boost;
using namespace json_spirit;

const Object emptyobj;

//static inline unsigned short GetDefaultRPCPort()
//{
    //return GetBoolArg("-testnet", false) ? 9909 : 9908;
//}

void RPCTypeCheck(const Array& params,
                  const list<Value_type>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    for (Value_type t : typesExpected)
    {
        if (params.size() <= i)
            break;

        const Value& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}
void RPCTypeCheck(const Object& o,
                  const map<string, Value_type>& typesExpected,
                  bool fAllowNull)
{
    for (const auto& t : typesExpected)
    {
        const Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == null_type)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first.c_str()));

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   Value_type_name[t.second], t.first.c_str(), Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

int64_t AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > MAX_MONEY)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    int64_t nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

Value ValueFromAmount(int64_t amount)
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
            Array params;
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

Value help(const Array& params, bool fHelp)
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

Value stop(const Array& params, bool fHelp)
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

void JSONRequest::parse(const Value& valRequest)
        {
            // Parse request
    if (valRequest.type() != obj_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
            const Object& request = valRequest.get_obj();

            // Parse id now so errors from here on will have the id
            id = find_value(request, "id");

            // Parse method
            Value valMethod = find_value(request, "method");
            if (valMethod.type() == null_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
            if (valMethod.type() != str_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
            if (strMethod != "getblocktemplate")
                printf("ThreadRPCServer method=%s\n", strMethod.c_str());

            // Parse params
            Value valParams = find_value(request, "params");
            if (valParams.type() == array_type)
                params = valParams.get_array();
            else if (valParams.type() == null_type)
                params = Array();
            else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static Object JSONRPCExecOne(const Value& req)
{
    Object rpc_result;

    JSONRequest jreq;
    try {
        jreq.parse(req);

        Value result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, Value::null, jreq.id);
        }
        catch (Object& objError)
        {
        rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
    }
    catch (std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(Value::null,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}


string JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

json_spirit::Value CRPCTable::execute(const std::string &strMethod, const json_spirit::Array &params) const
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
        Value result;
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
