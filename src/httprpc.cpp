// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2024 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "httprpc.h"

#include "base58.h"
#include "httpserver.h"
#include "rpcprotocol.h"
#include "rpcserver.h"
#include "random.h"
#include "sync.h"
#include "util.h"
#include "ui_interface.h"

#include <boost/algorithm/string.hpp> // boost::trim

#undef printf
#include <string.h>
#define printf OutputDebugStringF

using namespace json_spirit;

/* Pre-base64-encoded authentication token */
static std::string strRPCUserColonPass;

/** Constant-time string comparison to make password guessing harder. */
static bool TimingResistantEqual(const std::string& a, const std::string& b)
{
    if (b.size() == 0)
        return a.size() == 0;
    size_t accumulator = a.size() ^ b.size();
    for (size_t i = 0; i < a.size(); i++)
        accumulator |= (size_t)(a[i] ^ b[i % b.size()]);
    return accumulator == 0;
}

static void JSONErrorReply(HTTPRequest* req, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();

    if (code == RPC_INVALID_REQUEST)
        nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND)
        nStatus = HTTP_NOT_FOUND;

    std::string strReply = JSONRPCReply(Value::null, Value(objError), id);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(nStatus, strReply);
}

static bool RPCAuthorized(const std::string& strAuth)
{
    if (strRPCUserColonPass.empty()) // Belt-and-suspenders measure if InitRPCAuthentication was not called
        return false;
    if (strAuth.substr(0, 6) != "Basic ")
        return false;
    std::string strUserPass64 = strAuth.substr(6);
    boost::trim(strUserPass64);
    std::string strUserPass = DecodeBase64(strUserPass64);
    return TimingResistantEqual(strUserPass, strRPCUserColonPass);
}

static void HTTPReq_JSONRPC(HTTPRequest* req, const std::string &)
{
    // JSONRPC handles only POST
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_METHOD_NOT_ALLOWED, "JSONRPC server handles only POST requests");
        return;
    }
    // Check authorization
    std::pair<bool, std::string> authHeader = req->GetHeader("authorization");
    if (!authHeader.first) {
        req->WriteHeader("WWW-Authenticate", "Basic realm=\"jsonrpc\"");
        req->WriteReply(HTTP_UNAUTHORIZED);
        return;
    }

    if (!RPCAuthorized(authHeader.second)) {
        printf("ThreadRPCServer incorrect password attempt from %s\n", req->GetPeer().ToStringIP().c_str());

        /* Deter brute-forcing
           If this results in a DoS the user really
           shouldn't have their RPC port exposed. */
        MilliSleep(250);

        req->WriteHeader("WWW-Authenticate", "Basic realm=\"jsonrpc\"");
        req->WriteReply(HTTP_UNAUTHORIZED);
        return;
    }

    JSONRequest jreq;
    try {
        // Parse request
        Value valRequest;
        if (!read_string(req->ReadBody(), valRequest))
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

        std::string strReply;
        // singleton request
        if (valRequest.type() == obj_type) {
            jreq.parse(valRequest);

            Value result = tableRPC.execute(jreq.strMethod, jreq.params);

            // Send reply
            strReply = JSONRPCReply(result, Value::null, jreq.id);

        // array of requests
        } else if (valRequest.type() == array_type)
            strReply = JSONRPCExecBatch(valRequest.get_array());
        else
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strReply);
    } catch (Object& objError) {
        JSONErrorReply(req, objError, jreq.id);
        return;
    } catch (std::exception& e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return;
    }
}

static bool InitRPCAuthentication()
{
    if (mapArgs["-rpcpassword"] == "")
    {
        unsigned char rand_pwd[32];
        GetRandBytes(rand_pwd, 32);
        std::string strWhatAmI = "To use versiond";
        if (mapArgs.count("-server"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-server\"");
        else if (mapArgs.count("-daemon"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-daemon\"");
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("%s, you must set a rpcpassword in the configuration file:\n %s\n"
              "It is recommended you use the following random password:\n"
              "rpcuser=versionrpc\n"
              "rpcpassword=%s\n"
              "(you do not need to remember this password)\n"
              "If the file does not exist, create it with owner-readable-only file permissions.\n"),
                strWhatAmI.c_str(),
                GetConfigFile().string().c_str(),
                EncodeBase58(&rand_pwd[0], &rand_pwd[0] + 32).c_str()),
            _("Error"), CClientUIInterface::MSG_ERROR);
        return false;
    }
    strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    return true;
}

bool StartHTTPRPC()
{
    printf("Starting HTTP RPC server\n");
    if (!InitRPCAuthentication())
        return false;

    RegisterHTTPHandler("/", true, HTTPReq_JSONRPC);
    return true;
}

void InterruptHTTPRPC()
{
    printf("Interrupting HTTP RPC server\n");
}

void StopHTTPRPC()
{
    printf("Stopping HTTP RPC server\n");
    UnregisterHTTPHandler("/", true);
}
