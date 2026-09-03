// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2024 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPRPC_H
#define BITCOIN_HTTPRPC_H

/** Register the JSON-RPC handler with the HTTP server and set up
 *  authentication. StartHTTPServer() must have been called first.
 */
bool StartHTTPRPC();
/** Interrupt HTTP RPC subsystem */
void InterruptHTTPRPC();
/** Stop HTTP RPC subsystem (unregister the handler) */
void StopHTTPRPC();

#endif // BITCOIN_HTTPRPC_H
