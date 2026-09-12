// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "ui_interface.h"
#include "qtipcserver.h"

#include <cstring>
#include <string>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace std;

// A single, fixed-name Unix domain datagram socket used to hand "version:" URI
// command-line args from a second launch off to the already-running instance,
// mirroring the boost::interprocess::message_queue this used to be built on:
// one send() == one message, delivered whole, no explicit connection/backlog.
static string IpcSocketPath()
{
    return "/tmp/." + string(BITCOINURI_QUEUE_NAME) + "-" + std::to_string(getuid()) + ".sock";
}

static bool IpcBuildAddr(struct sockaddr_un& addr)
{
    string path = IpcSocketPath();
    if (path.size() >= sizeof(addr.sun_path))
        return false;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    return true;
}

bool IpcSendUri(const char* strURI)
{
    struct sockaddr_un addr;
    if (!IpcBuildAddr(addr))
        return false;

    int fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    bool fSent = false;
    if (::connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0)
        fSent = (::send(fd, strURI, strlen(strURI), 0) >= 0);

    ::close(fd);
    return fSent;
}

void ipcShutdown()
{
    string path = IpcSocketPath();
    ::unlink(path.c_str());
}

void ipcThread(void* parg)
{
    RenameThread("version-ipc");

    int fd = (int)(intptr_t)parg;
    char strBuf[257];
    while (!fShutdown)
    {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int ret = ::poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN))
        {
            ssize_t n = ::recv(fd, strBuf, sizeof(strBuf) - 1, 0);
            if (n > 0)
            {
                uiInterface.ThreadSafeHandleURI(std::string(strBuf, n));
                MilliSleep(1000);
            }
        }
    }
    ::close(fd);
    ipcShutdown();
}

void ipcInit()
{
#ifdef MAC_OSX
    // TODO: implement bitcoin: URI handling the Mac Way
    return;
#endif
#ifdef WIN32
    // TODO: implement version: URI handling on Windows
    return;
#endif

    struct sockaddr_un addr;
    if (!IpcBuildAddr(addr))
        return;

    // Clear out a stale socket left behind by a crashed previous instance
    // before binding, so we always start with an empty receive queue.
    ::unlink(addr.sun_path);

    int fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return;

    if (::bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        ::close(fd);
        return;
    }

    if (!NewThread(ipcThread, (void*)(intptr_t)fd))
        ::close(fd);
}
