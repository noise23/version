// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2012 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_DB_H
#define BITCOIN_DB_H

#include "main.h"
#include "cleanse.h"

#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include <db_cxx.h>
#include <sqlite3/sqlite3.h>

class CAddress;
class CAddrMan;
class CBlockLocator;
class CDiskBlockIndex;
class CDiskTxPos;
class CMasterKey;
class COutPoint;
class CTxIndex;
class CWallet;
class CWalletTx;

extern unsigned int nWalletDBUpdated;

void ThreadFlushWalletDB(void* parg);
bool BackupWallet(const CWallet& wallet, const std::string& strDest);
bool DumpWallet(CWallet* pwallet, const std::string& strDest);
bool ImportWallet(CWallet* pwallet, const std::string& strLocation);

/** On-disk wallet database format. Newly created wallets are always SQLITE;
 * BDB is kept only so wallets created by older versions of this client keep
 * working (read and write) without requiring a migration. */
enum class WalletDBFormat
{
    BDB,
    SQLITE,
};

/** Sniff a wallet file's on-disk format by peeking at its header, without
 * opening it through either backend. Files that don't exist yet are reported
 * as SQLITE, since that's what a brand-new wallet will be created as. */
WalletDBFormat DetectWalletDBFormat(const std::filesystem::path& pathFile);

class CDBEnv
{
private:
    bool fDbEnvInit;
    bool fMockDb;
    std::filesystem::path pathEnv;
    std::string strPath;

    void EnvShutdown();

public:
    mutable CCriticalSection cs_db;
    DbEnv dbenv;
    std::map<std::string, int> mapFileUseCount;
    std::map<std::string, Db*> mapDb;

    CDBEnv();
    ~CDBEnv();
    void MakeMock();
    bool IsMock() { return fMockDb; };

    /*
     * Verify that database file strFile is OK. If it is not,
     * call the callback to try to recover.
     * This must be called BEFORE strFile is opened.
     * Returns true if strFile is OK.
     */
    enum VerifyResult { VERIFY_OK, RECOVER_OK, RECOVER_FAIL };
    VerifyResult Verify(std::string strFile, bool (*recoverFunc)(CDBEnv& dbenv, std::string strFile));
    /*
     * Salvage data from a file that Verify says is bad.
     * fAggressive sets the DB_AGGRESSIVE flag (see berkeley DB->verify() method documentation).
     * Appends binary key/value pairs to vResult, returns true if successful.
     * NOTE: reads the entire database into memory, so cannot be used
     * for huge databases.
     */
    typedef std::pair<std::vector<unsigned char>, std::vector<unsigned char> > KeyValPair;
    bool Salvage(std::string strFile, bool fAggressive, std::vector<KeyValPair>& vResult);

    bool Open(std::filesystem::path pathEnv_);
    void Close();
    void Flush(bool fShutdown);
    void CheckpointLSN(std::string strFile);

    void CloseDb(const std::string& strFile);
    bool RemoveDb(const std::string& strFile);

    DbTxn *TxnBegin(int flags=DB_TXN_WRITE_NOSYNC)
    {
        DbTxn* ptxn = NULL;
        int ret = dbenv.txn_begin(NULL, &ptxn, flags);
        if (!ptxn || ret != 0)
            return NULL;
        return ptxn;
    }
};

extern CDBEnv bitdb;

/** Opaque cursor over a wallet database's key/value pairs, wrapping either a
 * Berkeley DB cursor or a SQLite prepared statement depending on which
 * backend the CDB that created it is using. */
class CDBCursor
{
    friend class CDB;
    Dbc* pdbc;
    sqlite3_stmt* pstmt;
public:
    CDBCursor() : pdbc(NULL), pstmt(NULL) {}
    ~CDBCursor() { close(); }
    void close()
    {
        if (pdbc) { pdbc->close(); pdbc = NULL; }
        if (pstmt) { sqlite3_finalize(pstmt); pstmt = NULL; }
    }
};

/** RAII class that provides access to a wallet database, backed by either
 * Berkeley DB (legacy wallets) or SQLite (new wallets). */
class CDB
{
protected:
    WalletDBFormat format;
    std::string strFile;
    bool fReadOnly;

    // Berkeley DB backend
    Db* pdb;
    DbTxn *activeTxn;

    // SQLite backend
    sqlite3* psqlite;
    bool fSqliteTxnActive;

    explicit CDB(const char* pszFile, const char* pszMode="r+");
    ~CDB() { Close(); }
public:
    void Close();
private:
    CDB(const CDB&);
    void operator=(const CDB&);

    // Byte-level primitives; Read/Write/Erase/Exists below do the
    // CDataStream (de)serialization and call down into these.
    bool ReadRaw(const std::vector<unsigned char>& vchKey, std::vector<unsigned char>& vchValue);
    bool WriteRaw(const std::vector<unsigned char>& vchKey, const std::vector<unsigned char>& vchValue, bool fOverwrite);
    bool EraseRaw(const std::vector<unsigned char>& vchKey);
    bool ExistsRaw(const std::vector<unsigned char>& vchKey);

protected:
    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        if (!pdb && !psqlite)
            return false;

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::vector<unsigned char> vchKey(ssKey.begin(), ssKey.end());

        std::vector<unsigned char> vchValue;
        if (!ReadRaw(vchKey, vchValue))
            return false;
        if (vchValue.empty())
            return false;

        // Unserialize value
        bool fOk = true;
        try {
            CDataStream ssValue(vchValue, SER_DISK, CLIENT_VERSION);
            ssValue >> value;
        }
        catch (std::exception &e) {
            fOk = false;
        }

        // vchValue may hold sensitive data (e.g. a private key); ssValue made
        // its own copy into a self-scrubbing buffer, so it's safe to wipe this one.
        memory_cleanse(vchValue.data(), vchValue.size());
        return fOk;
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite=true)
    {
        if (!pdb && !psqlite)
            return false;
        if (fReadOnly)
            assert(!"Write called on database in read-only mode");

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::vector<unsigned char> vchKey(ssKey.begin(), ssKey.end());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;
        std::vector<unsigned char> vchValue(ssValue.begin(), ssValue.end());

        bool fOk = WriteRaw(vchKey, vchValue, fOverwrite);

        // vchValue may hold sensitive data (e.g. a private key); ssValue is
        // its own, self-scrubbing copy, so it's safe to wipe this one now.
        memory_cleanse(vchValue.data(), vchValue.size());
        return fOk;
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!pdb && !psqlite)
            return false;
        if (fReadOnly)
            assert(!"Erase called on database in read-only mode");

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::vector<unsigned char> vchKey(ssKey.begin(), ssKey.end());

        return EraseRaw(vchKey);
    }

    template<typename K>
    bool Exists(const K& key)
    {
        if (!pdb && !psqlite)
            return false;

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::vector<unsigned char> vchKey(ssKey.begin(), ssKey.end());

        return ExistsRaw(vchKey);
    }

    CDBCursor* GetCursor();
    int ReadAtCursor(CDBCursor* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags=DB_NEXT);

public:
    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }

    bool static Rewrite(const std::string& strFile, const char* pszSkip = NULL);

    /** One-way migration of an existing BDB-format wallet file to SQLite.
     * The original file is preserved alongside the new one under a .bdb.bak
     * name. Requires the BDB environment (bitdb) to already be open. */
    bool static MigrateBDBToSQLite(const std::string& strWalletFile, std::string& strError);
};

/** Access to the (IP) address database (peers.dat) */
class CAddrDB
{
private:
    std::filesystem::path pathAddr;
public:
    CAddrDB();
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
};

#endif // BITCOIN_DB_H
