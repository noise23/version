#define BITCOINURI_QUEUE_NAME "BitcoinURI"

void ipcInit();
void ipcShutdown();

/** Try to hand a version: URI to an already-running instance via the IPC
 * socket. Returns true if it was delivered to a listening instance. */
bool IpcSendUri(const char* strURI);
