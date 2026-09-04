// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2024 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "httpserver.h"

#include "compat.h"
#include "util.h"
#include "netbase.h"
#include "rpcprotocol.h"  // for HTTP status codes
#include "rpcserver.h"    // for GetDefaultRPCPort()
#include "serialize.h"    // for MAX_SIZE
#include "sync.h"
#include "ui_interface.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <deque>
#include <memory>
#include <vector>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/bind/bind.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>

/** Maximum size of http request (request line + headers) */
static const size_t MAX_HEADERS_SIZE = 8192;

/** HTTP request work item */
class HTTPWorkItem : public HTTPClosure
{
public:
    HTTPWorkItem(HTTPRequest* req, const std::string &path, const HTTPRequestHandler& func):
        req(req), path(path), func(func)
    {
    }
    void operator()()
    {
        // A handler is expected to catch its own errors and craft a proper
        // reply, but if one escapes we must not let it unwind out of the
        // worker thread (that would call std::terminate). Log it, and make
        // sure the client gets a response instead of hanging.
        try {
            func(req.get(), path);
        } catch (const std::exception& e) {
            printf("HTTP: unhandled exception while processing request: %s\n", e.what());
            if (!req->ReplySent())
                req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, e.what());
        } catch (...) {
            printf("HTTP: unhandled non-standard exception while processing request\n");
            if (!req->ReplySent())
                req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, "Internal server error");
        }
    }

    boost::scoped_ptr<HTTPRequest> req;

private:
    std::string path;
    HTTPRequestHandler func;
};

/** Simple work queue for distributing work over multiple threads.
 * Work items are simply callable objects.
 */
template <typename WorkItem>
class WorkQueue
{
private:
    /** Mutex protects entire object */
    boost::mutex cs;
    boost::condition_variable cond;
    std::deque<WorkItem*> queue;
    bool running;
    size_t maxDepth;

public:
    WorkQueue(size_t maxDepth) : running(true),
                                 maxDepth(maxDepth)
    {
    }
    /* Precondition: worker threads have all stopped */
    ~WorkQueue()
    {
        while (!queue.empty()) {
            delete queue.front();
            queue.pop_front();
        }
    }
    /** Enqueue a work item */
    bool Enqueue(WorkItem* item)
    {
        boost::unique_lock<boost::mutex> lock(cs);
        if (queue.size() >= maxDepth) {
            return false;
        }
        queue.push_back(item);
        cond.notify_one();
        return true;
    }
    /** Thread function */
    void Run()
    {
        // `running` is only ever read/written while holding `cs`; the locked
        // check below is what actually terminates the loop.
        while (true) {
            WorkItem* i = 0;
            {
                boost::unique_lock<boost::mutex> lock(cs);
                while (running && queue.empty())
                    cond.wait(lock);
                if (!running)
                    break;
                i = queue.front();
                queue.pop_front();
            }
            (*i)();
            delete i;
        }
    }
    /** Interrupt and exit loops */
    void Interrupt()
    {
        boost::unique_lock<boost::mutex> lock(cs);
        running = false;
        cond.notify_all();
    }

    /** Return current depth of queue */
    size_t Depth()
    {
        boost::unique_lock<boost::mutex> lock(cs);
        return queue.size();
    }
};

struct HTTPPathHandler
{
    HTTPPathHandler() {}
    HTTPPathHandler(std::string prefix, bool exactMatch, HTTPRequestHandler handler):
        prefix(prefix), exactMatch(exactMatch), handler(handler)
    {
    }
    std::string prefix;
    bool exactMatch;
    HTTPRequestHandler handler;
};

/** HTTP module state */

//! libevent event loop
static struct event_base* eventBase = 0;
//! HTTP server
struct evhttp* eventHTTP = 0;
//! Work queue for handling longer requests off the event loop thread
static WorkQueue<HTTPClosure>* workQueue = 0;
//! Handlers for (sub)paths. Read from the event-loop thread, mutated from the
//! init/shutdown threads via (Un)RegisterHTTPHandler, so guard every access.
static boost::mutex g_httppathhandlers_mutex;
static std::vector<HTTPPathHandler> pathHandlers;
//! Bound listening sockets. Removing these lets the event loop exit on its own.
static std::vector<evhttp_bound_socket*> boundSockets;
//! The event loop dispatch thread
static boost::thread threadHTTP;
//! The request worker threads
static boost::thread_group threadHTTPWorkers;
//! Set when the server is shutting down
static bool fHTTPStopped = false;

/** Check if a network address is allowed to access the HTTP server.
 *  Uses the same wildcard matching semantics as the legacy asio RPC server,
 *  so existing -rpcallowip configuration keeps working unchanged.
 */
static bool ClientAllowed(const CNetAddr& netaddr)
{
    if (!netaddr.IsValid())
        return false;
    if (netaddr.IsLocal())
        return true;
    const std::string strAddress = netaddr.ToStringIP();
    const std::vector<std::string>& vAllow = mapMultiArgs["-rpcallowip"];
    for (unsigned int i = 0; i < vAllow.size(); i++)
        if (WildcardMatch(strAddress, vAllow[i]))
            return true;
    return false;
}

/** HTTP request method as string - use for logging only */
static std::string RequestMethodString(HTTPRequest::RequestMethod m)
{
    switch (m) {
    case HTTPRequest::GET:
        return "GET";
    case HTTPRequest::POST:
        return "POST";
    case HTTPRequest::HEAD:
        return "HEAD";
    case HTTPRequest::PUT:
        return "PUT";
    default:
        return "unknown";
    }
}

/** HTTP request callback */
static void http_request_cb(struct evhttp_request* req, void* arg)
{
    std::unique_ptr<HTTPRequest> hreq(new HTTPRequest(req));

    printf("HTTP: received a %s request for %s from %s\n",
           RequestMethodString(hreq->GetRequestMethod()).c_str(), hreq->GetURI().c_str(), hreq->GetPeer().ToStringIPPort().c_str());

    // Early address-based allow check
    if (!ClientAllowed(hreq->GetPeer())) {
        hreq->WriteReply(HTTP_FORBIDDEN);
        return;
    }

    // Early reject unknown HTTP methods
    if (hreq->GetRequestMethod() == HTTPRequest::UNKNOWN) {
        hreq->WriteReply(HTTP_METHOD_NOT_ALLOWED);
        return;
    }

    // Find registered handler for prefix
    std::string strURI = hreq->GetURI();
    std::string path;
    HTTPRequestHandler handler;
    bool foundHandler = false;
    {
        boost::unique_lock<boost::mutex> lock(g_httppathhandlers_mutex);
        std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
        std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();
        for (; i != iend; ++i) {
            bool match = false;
            if (i->exactMatch)
                match = (strURI == i->prefix);
            else
                match = (strURI.substr(0, i->prefix.size()) == i->prefix);
            if (match) {
                path = strURI.substr(i->prefix.size());
                handler = i->handler;
                foundHandler = true;
                break;
            }
        }
    }

    // Dispatch to worker thread
    if (foundHandler) {
        std::unique_ptr<HTTPWorkItem> item(new HTTPWorkItem(hreq.release(), path, handler));
        assert(workQueue);
        if (workQueue->Enqueue(item.get()))
            item.release(); /* if true, queue took ownership */
        else
            item->req->WriteReply(HTTP_INTERNAL_SERVER_ERROR, "Work queue depth exceeded");
    } else {
        hreq->WriteReply(HTTP_NOT_FOUND);
    }
}

/** Callback to reject HTTP requests after shutdown has been requested. */
static void http_reject_request_cb(struct evhttp_request* req, void*)
{
    printf("HTTP: rejecting request while shutting down\n");
    evhttp_send_error(req, HTTP_SERVICE_UNAVAILABLE, NULL);
}

/** Event dispatcher thread */
static void ThreadHTTP(struct event_base* base, struct evhttp* http)
{
    RenameThread("version-http");
    printf("HTTP: entering event loop\n");
    event_base_dispatch(base);
    // Event loop will be interrupted by InterruptHTTPServer()
    printf("HTTP: exited event loop\n");
}

/** Bind HTTP server to specified addresses */
static bool HTTPBindAddresses(struct evhttp* http)
{
    int defaultPort = GetArg("-rpcport", GetDefaultRPCPort());
    int nBound = 0;
    std::vector<std::pair<std::string, uint16_t> > endpoints;

    // Determine what addresses to bind to
    if (!mapArgs.count("-rpcallowip")) { // Default to loopback if not allowing external IPs
        endpoints.push_back(std::make_pair("::1", defaultPort));
        endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));
        if (mapArgs.count("-rpcbind")) {
            printf("WARNING: option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect\n");
        }
    } else if (mapArgs.count("-rpcbind")) { // Specific bind address
        const std::vector<std::string>& vbind = mapMultiArgs["-rpcbind"];
        for (std::vector<std::string>::const_iterator i = vbind.begin(); i != vbind.end(); ++i) {
            int port = defaultPort;
            std::string host;
            SplitHostPort(*i, port, host);
            endpoints.push_back(std::make_pair(host, port));
        }
    } else { // No specific bind address specified, bind to any
        endpoints.push_back(std::make_pair("::", defaultPort));
        endpoints.push_back(std::make_pair("0.0.0.0", defaultPort));
    }

    // Bind addresses
    for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) {
        printf("HTTP: binding RPC on address %s port %i\n", i->first.c_str(), i->second);
        evhttp_bound_socket *bind_handle = evhttp_bind_socket_with_handle(http, i->first.empty() ? NULL : i->first.c_str(), i->second);
        if (bind_handle) {
            nBound += 1;
            boundSockets.push_back(bind_handle);
        } else {
            printf("Binding RPC on address %s port %i failed.\n", i->first.c_str(), i->second);
        }
    }
    return nBound > 0;
}

/** Simple wrapper to set thread name and run work queue */
static void HTTPWorkQueueRun(WorkQueue<HTTPClosure>* queue)
{
    RenameThread("version-httpworker");
    queue->Run();
}

bool StartHTTPServer()
{
    struct evhttp* http = 0;
    struct event_base* base = 0;

    if (GetBoolArg("-rpcssl", false)) {
        uiInterface.ThreadSafeMessageBox(
            "SSL mode for RPC (-rpcssl) is no longer supported. Use a reverse proxy (e.g. stunnel) instead.",
            "", CClientUIInterface::MSG_ERROR);
        return false;
    }

#ifdef WIN32
    evthread_use_windows_threads();
#else
    evthread_use_pthreads();
#endif

    base = event_base_new();
    if (!base) {
        printf("Couldn't create an event_base: exiting\n");
        return false;
    }

    /* Create a new evhttp object to handle requests. */
    http = evhttp_new(base);
    if (!http) {
        printf("couldn't create evhttp. Exiting.\n");
        event_base_free(base);
        return false;
    }

    evhttp_set_timeout(http, GetArg("-rpcclienttimeout", 30));
    evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE);
    evhttp_set_max_body_size(http, MAX_SIZE);
    evhttp_set_gencb(http, http_request_cb, NULL);

    if (!HTTPBindAddresses(http)) {
        printf("Unable to bind any endpoint for RPC server\n");
        evhttp_free(http);
        event_base_free(base);
        return false;
    }

    int workQueueDepth = std::max((int)GetArg("-rpcworkqueue", 16), 1);
    int rpcThreads = std::max((int)GetArg("-rpcthreads", 4), 1);
    printf("HTTP: creating work queue of depth %d and %d worker threads\n", workQueueDepth, rpcThreads);
    workQueue = new WorkQueue<HTTPClosure>(workQueueDepth);

    fHTTPStopped = false;
    eventBase = base;
    eventHTTP = http;

    threadHTTP = boost::thread(boost::bind(&ThreadHTTP, base, http));
    for (int i = 0; i < rpcThreads; i++)
        threadHTTPWorkers.create_thread(boost::bind(&HTTPWorkQueueRun, workQueue));

    return true;
}

void InterruptHTTPServer()
{
    printf("HTTP: interrupting HTTP server\n");
    if (eventHTTP) {
        // Reject all new requests while shutting down; in-flight requests
        // that have already been dispatched are still allowed to finish and
        // to write their reply back through the event loop.
        evhttp_set_gencb(eventHTTP, http_reject_request_cb, NULL);
    }
    if (workQueue)
        workQueue->Interrupt();
}

void StopHTTPServer()
{
    printf("HTTP: stopping HTTP server\n");
    if (fHTTPStopped)
        return;
    fHTTPStopped = true;

    // 1. Drain and join the request workers so no worker is still holding a
    //    request when we tear down the event loop.
    if (workQueue) {
        printf("HTTP: waiting for HTTP worker threads to exit\n");
        workQueue->Interrupt();
        threadHTTPWorkers.join_all();
        delete workQueue;
        workQueue = 0;
    }

    // 2. Stop listening. The bound sockets are what keep the event loop alive;
    //    once they are removed and all client connections have closed (see the
    //    "Connection: close" header added by WriteReply during shutdown), the
    //    loop returns on its own - no arbitrary timeout needed.
    for (size_t i = 0; i < boundSockets.size(); i++)
        evhttp_del_accept_socket(eventHTTP, boundSockets[i]);
    boundSockets.clear();

    // 3. Wait for the event loop thread to finish. As a safety net against a
    //    misbehaving client holding an idle keep-alive connection open, cap
    //    the wait; well-behaved clients (including our own CLI) send
    //    "Connection: close" and never reach this.
    if (eventBase) {
        printf("HTTP: waiting for HTTP event thread to exit\n");
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        event_base_loopexit(eventBase, &tv);
    }
    if (threadHTTP.joinable())
        threadHTTP.join();

    if (eventHTTP) {
        evhttp_free(eventHTTP);
        eventHTTP = 0;
    }
    if (eventBase) {
        event_base_free(eventBase);
        eventBase = 0;
    }
    printf("HTTP: server stopped\n");
}

struct event_base* EventBase()
{
    return eventBase;
}

static void httpevent_callback_fn(evutil_socket_t, short, void* data)
{
    // Static handler simply passes through execution flow to _handle method
    HTTPEvent* self = ((HTTPEvent*)data);
    self->handler();
    if (self->deleteWhenTriggered)
        delete self;
}

HTTPEvent::HTTPEvent(struct event_base* base, bool deleteWhenTriggered, const boost::function<void(void)>& handler):
    deleteWhenTriggered(deleteWhenTriggered), handler(handler)
{
    ev = event_new(base, -1, 0, httpevent_callback_fn, this);
    assert(ev);
}
HTTPEvent::~HTTPEvent()
{
    event_free(ev);
}
void HTTPEvent::trigger(struct timeval* tv)
{
    if (tv == NULL)
        event_active(ev, 0, 0); // immediately trigger event in main thread
    else
        evtimer_add(ev, tv); // trigger after timeval passed
}
HTTPRequest::HTTPRequest(struct evhttp_request* req) : req(req),
                                                       replySent(false)
{
}
HTTPRequest::~HTTPRequest()
{
    if (!replySent) {
        // Keep track of whether reply was sent to avoid request leaks
        printf("%s: Unhandled request\n", __func__);
        WriteReply(HTTP_INTERNAL_SERVER_ERROR, "Unhandled request");
    }
    // evhttpd cleans up the request, as long as a reply was sent.
}

std::pair<bool, std::string> HTTPRequest::GetHeader(const std::string& hdr)
{
    const struct evkeyvalq* headers = evhttp_request_get_input_headers(req);
    assert(headers);
    const char* val = evhttp_find_header(headers, hdr.c_str());
    if (val)
        return std::make_pair(true, val);
    else
        return std::make_pair(false, "");
}

std::string HTTPRequest::ReadBody()
{
    struct evbuffer* buf = evhttp_request_get_input_buffer(req);
    if (!buf)
        return "";
    size_t size = evbuffer_get_length(buf);
    const char* data = (const char*)evbuffer_pullup(buf, size);
    if (!data) // returns NULL in case of empty buffer
        return "";
    std::string rv(data, size);
    evbuffer_drain(buf, size);
    return rv;
}

void HTTPRequest::WriteHeader(const std::string& hdr, const std::string& value)
{
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    assert(headers);
    evhttp_add_header(headers, hdr.c_str(), value.c_str());
}

/** Closure sent to main thread to request a reply to be sent to
 * a HTTP request.
 * Replies must be sent in the main loop in the main http thread,
 * this cannot be done from worker threads.
 */
static void http_send_reply(struct evhttp_request* req, int nStatus)
{
    evhttp_send_reply(req, nStatus, NULL, NULL);
}

void HTTPRequest::WriteReply(int nStatus, const std::string& strReply)
{
    assert(!replySent && req);
    if (fShutdown) {
        // Tell libevent to close this (otherwise persistent, for HTTP/1.1)
        // connection once the reply is sent, so the event loop can drain and
        // exit cleanly during shutdown instead of waiting on the timeout.
        WriteHeader("Connection", "close");
    }
    // Send event to main http thread to send reply message
    struct evbuffer* evb = evhttp_request_get_output_buffer(req);
    assert(evb);
    evbuffer_add(evb, strReply.data(), strReply.size());
    HTTPEvent* ev = new HTTPEvent(eventBase, true,
                                  boost::bind(http_send_reply, req, nStatus));
    ev->trigger(0);
    replySent = true;
    req = 0; // transferred back to main thread
}

CService HTTPRequest::GetPeer()
{
    evhttp_connection* con = evhttp_request_get_connection(req);
    CService peer;
    if (con) {
        // evhttp retains ownership over returned address string
        const char* address = "";
        uint16_t port = 0;
        evhttp_connection_get_peer(con, (char**)&address, &port);
        LookupNumeric(address, peer, port);
    }
    return peer;
}

std::string HTTPRequest::GetURI()
{
    return evhttp_request_get_uri(req);
}

HTTPRequest::RequestMethod HTTPRequest::GetRequestMethod()
{
    switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_GET:
        return GET;
    case EVHTTP_REQ_POST:
        return POST;
    case EVHTTP_REQ_HEAD:
        return HEAD;
    case EVHTTP_REQ_PUT:
        return PUT;
    default:
        return UNKNOWN;
    }
}

void RegisterHTTPHandler(const std::string &prefix, bool exactMatch, const HTTPRequestHandler &handler)
{
    printf("HTTP: registering handler for %s (exactmatch %d)\n", prefix.c_str(), exactMatch);
    boost::unique_lock<boost::mutex> lock(g_httppathhandlers_mutex);
    pathHandlers.push_back(HTTPPathHandler(prefix, exactMatch, handler));
}

void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch)
{
    boost::unique_lock<boost::mutex> lock(g_httppathhandlers_mutex);
    std::vector<HTTPPathHandler>::iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::iterator iend = pathHandlers.end();
    for (; i != iend; ++i)
        if (i->prefix == prefix && i->exactMatch == exactMatch)
            break;
    if (i != iend)
    {
        printf("HTTP: unregistering handler for %s (exactmatch %d)\n", prefix.c_str(), exactMatch);
        pathHandlers.erase(i);
    }
}
