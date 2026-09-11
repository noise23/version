// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcclient.h"

#include "rpcprotocol.h"
#include "rpcserver.h" // for GetDefaultRPCPort ()
#include "util.h"
#include "ui_interface.h"

#include <stdio.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

using namespace std;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:
    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}
};

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0) {}
    int status;
    std::string body;
};

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting, but
         * I'm not sure how to find out which one. We also don't really care. */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf) {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

UniValue CallRPC(const string& strMethod, const UniValue& params)
{
    if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
        throw runtime_error(strprintf(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
            "If the file does not exist, create it with owner-readable-only file permissions."),
            GetConfigFile().string().c_str()));

    if (GetBoolArg("-rpcssl"))
        throw runtime_error("SSL mode for RPC (-rpcssl) is no longer supported. Use a reverse proxy (e.g. stunnel) instead.");

    std::string host = GetArg("-rpcconnect", "127.0.0.1");
    int port = GetArg("-rpcport", GetDefaultRPCPort());

    struct event_base *base = event_base_new();
    if (!base)
        throw runtime_error("cannot create event_base");

    struct evhttp_connection *evcon = evhttp_connection_base_new(base, NULL, host.c_str(), port);
    if (evcon == NULL) {
        event_base_free(base);
        throw runtime_error("create connection failed");
    }
    evhttp_connection_set_timeout(evcon, GetArg("-rpctimeout", 30));

    HTTPReply response;
    struct evhttp_request *req = evhttp_request_new(http_request_done, (void*)&response);
    if (req == NULL) {
        evhttp_connection_free(evcon);
        event_base_free(base);
        throw runtime_error("create http request failed");
    }

    // HTTP basic authentication
    string strUserPass64 = EncodeBase64(mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]);
    struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (string("Basic ") + strUserPass64).c_str());

    // Attach request data
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    struct evbuffer *output_buffer = evhttp_request_get_output_buffer(req);
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/");
    if (r != 0) {
        evhttp_connection_free(evcon);
        event_base_free(base);
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base);
    evhttp_connection_free(evcon);
    event_base_free(base);

    if (response.status == 0)
        throw CConnectionFailed("couldn't connect to server");
    else if (response.status == HTTP_UNAUTHORIZED)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw runtime_error("no response from server");

    // Parse reply
    UniValue valReply;
    if (!valReply.read(response.body))
        throw runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}

// Marker tags distinguishing UniValue's merged VARR/VOBJ type at the
// ConvertTo<> call sites below (json_spirit had distinct Array/Object types).
struct AsArray {};
struct AsObject {};

template<typename T>
static void CheckConvertedType(const UniValue& value);
template<> void CheckConvertedType<bool>(const UniValue& value)
{
    if (!value.isBool())
        throw runtime_error("JSON value is not a boolean as expected");
}
template<> void CheckConvertedType<int64_t>(const UniValue& value)
{
    if (!value.isNum())
        throw runtime_error("JSON value is not a number as expected");
}
template<> void CheckConvertedType<double>(const UniValue& value)
{
    if (!value.isNum())
        throw runtime_error("JSON value is not a number as expected");
}
template<> void CheckConvertedType<AsArray>(const UniValue& value)
{
    if (!value.isArray())
        throw runtime_error("JSON value is not an array as expected");
}
template<> void CheckConvertedType<AsObject>(const UniValue& value)
{
    if (!value.isObject())
        throw runtime_error("JSON value is not an object as expected");
}

template<typename T>
void ConvertTo(UniValue& value, bool fAllowNull=false)
{
    if (fAllowNull && value.isNull())
        return;
    if (value.isStr())
    {
        // Reinterpret string as unquoted json value
        UniValue value2;
        string strJSON = value.get_str();
        if (!value2.read(strJSON))
            throw runtime_error(string("Error parsing JSON:")+strJSON);
        if (!(fAllowNull && value2.isNull()))
            CheckConvertedType<T>(value2);
        value = value2;
    }
    else
    {
        CheckConvertedType<T>(value);
    }
}

// Convert strings to command-specific RPC representation
UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    // Held as a plain vector (rather than a UniValue array) while converting
    // in place, since UniValue's operator[] is const-only.
    std::vector<UniValue> params;
    for (const std::string &param : strParams)
        params.emplace_back(param);

    int n = params.size();

    //
    // Special case non-string parameter types
    //
    if (strMethod == "stop"                   && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "settxfee"               && n > 0) ConvertTo<double>(params[0]);
    if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "getreceivedbyaccount"   && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "listreceivedbyaccount"  && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "listreceivedbyaccount"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getbalance"             && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "getblock"               && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblockbynumber"       && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "getblockbynumber"       && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblockhash"           && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "move"                   && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "move"                   && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "sendfrom"               && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "sendfrom"               && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "listtransactions"       && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "listtransactions"       && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "listaccounts"           && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "walletpassphrase"       && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "walletpassphrase"       && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "getblocktemplate"       && n > 0) ConvertTo<AsObject>(params[0]);
    if (strMethod == "listsinceblock"         && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "sendalert"              && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "sendalert"              && n > 3) ConvertTo<int64_t>(params[3]);
    if (strMethod == "sendalert"              && n > 4) ConvertTo<int64_t>(params[4]);
    if (strMethod == "sendalert"              && n > 5) ConvertTo<int64_t>(params[5]);
    if (strMethod == "sendalert"              && n > 6) ConvertTo<int64_t>(params[6]);
    if (strMethod == "sendmany"               && n > 1) ConvertTo<AsObject>(params[1]);
    if (strMethod == "sendmany"               && n > 2) ConvertTo<int64_t>(params[2]);
    if (strMethod == "reservebalance"          && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "reservebalance"          && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "addmultisigaddress"      && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "addmultisigaddress"     && n > 1) ConvertTo<AsArray>(params[1]);
    if (strMethod == "listunspent"            && n > 0) ConvertTo<int64_t>(params[0]);
    if (strMethod == "listunspent"            && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "listunspent"            && n > 2) ConvertTo<AsArray>(params[2]);
    if (strMethod == "getrawtransaction"      && n > 1) ConvertTo<int64_t>(params[1]);
    if (strMethod == "createrawtransaction"   && n > 0) ConvertTo<AsArray>(params[0]);
    if (strMethod == "createrawtransaction"   && n > 1) ConvertTo<AsObject>(params[1]);
    if (strMethod == "signrawtransaction"     && n > 1) ConvertTo<AsArray>(params[1], true);
    if (strMethod == "signrawtransaction"     && n > 2) ConvertTo<AsArray>(params[2], true);
    if (strMethod == "setstaking"            && n > 0) ConvertTo<bool>(params[0]);

    UniValue ret(UniValue::VARR);
    for (UniValue& p : params)
        ret.push_back(std::move(p));
    return ret;
}

int CommandLineRPC(int argc, char *argv[])
{
    string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2)
            throw runtime_error("too few parameters");
        string strMethod = argv[1];

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]);
        UniValue params = RPCConvertValues(strMethod, strParams);

        // Execute and handle connection failures with -rpcwait
        const bool fWait = GetBoolArg("-rpcwait", false);
        do {
            try {
                UniValue reply = CallRPC(strMethod, params);

                // Parse reply
                const UniValue& result = find_value(reply, "result");
                const UniValue& error  = find_value(reply, "error");

                if (!error.isNull())
                {
                    // Error
                    strPrint = "error: " + error.write();
                    int code = find_value(error.get_obj(), "code").get_int();
                    nRet = abs(code);
                }
                else
                {
                    // Result
                    if (result.isNull())
                        strPrint = "";
                    else if (result.isStr())
                        strPrint = result.get_str();
                    else
                        strPrint = result.write(2);
                }
                // Connection succeeded, no need to retry.
                break;
            }
            catch (const CConnectionFailed&)
            {
                if (fWait)
                    MilliSleep(1000);
                else
                    throw;
            }
        } while (fWait);
    }
    catch (std::exception& e)
    {
        strPrint = string("error: ") + e.what();
        nRet = 87;
    }
    catch (...)
    {
        PrintException(NULL, "CommandLineRPC()");
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}
