// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013-2026 The Version developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"
#include "net.h"
#include "util.h"
#include <filesystem>
#include <sstream>
#include <cstdio>

#ifndef WIN32
#include "sys/stat.h"
#endif

using namespace std;

unsigned int nWalletDBUpdated;

//
// Format detection
//

WalletDBFormat DetectWalletDBFormat(const std::filesystem::path& pathFile)
{
    // SQLite files begin with this fixed 16-byte magic header. If we can't
    // even read that many bytes (file missing, empty, or truncated), treat it
    // as "will be created as SQLite" -- the only case that matters here is a
    // brand-new wallet, which is always SQLite.
    static const char pchSqliteMagic[16] = "SQLite format 3";

    FILE* file = fopen(pathFile.string().c_str(), "rb");
    if (!file)
        return WalletDBFormat::SQLITE;

    char pchHeader[16];
    size_t nRead = fread(pchHeader, 1, sizeof(pchHeader), file);
    fclose(file);

    if (nRead == sizeof(pchHeader) && memcmp(pchHeader, pchSqliteMagic, sizeof(pchHeader)) == 0)
        return WalletDBFormat::SQLITE;

    return WalletDBFormat::BDB;
}

//
// CDBEnv (Berkeley DB environment; only used by BDB-format wallets)
//

CDBEnv bitdb;

void CDBEnv::EnvShutdown()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;
    int ret = dbenv.close(0);
    if (ret != 0)
        printf("EnvShutdown exception: %s (%d)\n", DbEnv::strerror(ret), ret);
    if (!fMockDb)
        DbEnv((u_int32_t)0).remove(strPath.c_str(), 0);
}

CDBEnv::CDBEnv() : dbenv(DB_CXX_NO_EXCEPTIONS)
{
    fDbEnvInit = false;
    fMockDb = false;
}

CDBEnv::~CDBEnv()
{
    EnvShutdown();
}

void CDBEnv::Close()
{
    EnvShutdown();
}

bool CDBEnv::Open(std::filesystem::path pathEnv_)
{
    if (fDbEnvInit)
        return true;

    if (fShutdown)
        return false;

    pathEnv = pathEnv_;
    std::filesystem::path pathDataDir = pathEnv;
    strPath = pathDataDir.string();
    std::filesystem::path pathLogDir = pathDataDir / "database";
    std::filesystem::create_directory(pathLogDir);
    std::filesystem::path pathErrorFile = pathDataDir / "db.log";
    printf("dbenv.open LogDir=%s ErrorFile=%s\n", pathLogDir.string().c_str(), pathErrorFile.string().c_str());

    unsigned int nEnvFlags = 0;
    if (GetBoolArg("-privdb", true))
        nEnvFlags |= DB_PRIVATE;

    int nDbCache = GetArg("-dbcache", 25);
    dbenv.set_lg_dir(pathLogDir.string().c_str());
    dbenv.set_cachesize(nDbCache / 1024, (nDbCache % 1024)*1048576, 1);
    dbenv.set_lg_bsize(1048576);
    dbenv.set_lg_max(10485760);
    dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_objects(10000);
    dbenv.set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
    dbenv.set_flags(DB_TXN_WRITE_NOSYNC, 1);
#ifdef DB_LOG_AUTO_REMOVE
    dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1);
#endif
    int ret = dbenv.open(strPath.c_str(),
                     DB_CREATE     |
                     DB_INIT_LOCK  |
                     DB_INIT_LOG   |
                     DB_INIT_MPOOL |
                     DB_INIT_TXN   |
                     DB_THREAD     |
                     DB_RECOVER    |
                     nEnvFlags,
                     S_IRUSR | S_IWUSR);
    if (ret != 0)
        return error("CDB() : error %s (%d) opening database environment", DbEnv::strerror(ret), ret);

    fDbEnvInit = true;
    fMockDb = false;
    return true;
}

void CDBEnv::MakeMock()
{
    if (fDbEnvInit)
        throw runtime_error("CDBEnv::MakeMock(): already initialized");

    if (fShutdown)
        throw runtime_error("CDBEnv::MakeMock(): during shutdown");

    printf("CDBEnv::MakeMock()\n");

    dbenv.set_cachesize(1, 0, 1);
    dbenv.set_lg_bsize(10485760*4);
    dbenv.set_lg_max(10485760);
    dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_objects(10000);
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
#ifdef DB_LOG_IN_MEMORY
    dbenv.log_set_config(DB_LOG_IN_MEMORY, 1);
#endif
    int ret = dbenv.open(NULL,
                     DB_CREATE     |
                     DB_INIT_LOCK  |
                     DB_INIT_LOG   |
                     DB_INIT_MPOOL |
                     DB_INIT_TXN   |
                     DB_THREAD     |
                     DB_PRIVATE,
                     S_IRUSR | S_IWUSR);
    if (ret > 0)
        throw runtime_error(strprintf("CDBEnv::MakeMock(): error %d opening database environment", ret));

    fDbEnvInit = true;
    fMockDb = true;
}

CDBEnv::VerifyResult CDBEnv::Verify(std::string strFile, bool (*recoverFunc)(CDBEnv& dbenv, std::string strFile))
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, NULL, 0);
    if (result == 0)
        return VERIFY_OK;
    else if (recoverFunc == NULL)
        return RECOVER_FAIL;

    // Try to recover:
    bool fRecovered = (*recoverFunc)(*this, strFile);
    return (fRecovered ? RECOVER_OK : RECOVER_FAIL);
}

bool CDBEnv::Salvage(std::string strFile, bool fAggressive,
                     std::vector<CDBEnv::KeyValPair >& vResult)
{
    LOCK(cs_db);
   assert(mapFileUseCount.count(strFile) == 0);

    u_int32_t flags = DB_SALVAGE;
    if (fAggressive) flags |= DB_AGGRESSIVE;

    stringstream strDump;

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, &strDump, flags);
    if (result != 0)
    {
        printf("ERROR: db salvage failed\n");
        return false;
    }

    // Format of bdb dump is ascii lines:
    // header lines...
    // HEADER=END
    // hexadecimal key
    // hexadecimal value
    // ... repeated
    // DATA=END

    string strLine;
    while (!strDump.eof() && strLine != "HEADER=END")
        getline(strDump, strLine); // Skip past header

    std::string keyHex, valueHex;
    while (!strDump.eof() && keyHex != "DATA=END")
    {
        getline(strDump, keyHex);
        if (keyHex != "DATA_END")
        {
            getline(strDump, valueHex);
            vResult.push_back(make_pair(ParseHex(keyHex),ParseHex(valueHex)));
        }
    }

    return (result == 0);
}

void CDBEnv::CheckpointLSN(std::string strFile)
{
    dbenv.txn_checkpoint(0, 0, 0);
    if (fMockDb)
        return;
    dbenv.lsn_reset(strFile.c_str(), 0);
}

void CDBEnv::CloseDb(const string& strFile)
{
    {
        LOCK(cs_db);
        if (mapDb[strFile] != NULL)
        {
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

bool CDBEnv::RemoveDb(const string& strFile)
{
    this->CloseDb(strFile);

    LOCK(cs_db);
    int rc = dbenv.dbremove(NULL, strFile.c_str(), NULL, DB_AUTO_COMMIT);
    return (rc == 0);
}

void CDBEnv::Flush(bool fShutdown)
{
    int64_t nStart = GetTimeMillis();
    // Flush log data to the actual data file
    //  on all files that are not in use
    printf("Flush(%s)%s\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
    if (!fDbEnvInit)
        return;
    {
        LOCK(cs_db);
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            printf("%s refcount=%d\n", strFile.c_str(), nRefCount);
            if (nRefCount == 0)
            {
                // Move log data to the dat file
                CloseDb(strFile);
                printf("%s checkpoint\n", strFile.c_str());
                dbenv.txn_checkpoint(0, 0, 0);
                printf("%s detach\n", strFile.c_str());
                if (!fMockDb)
                    dbenv.lsn_reset(strFile.c_str(), 0);
                printf("%s closed\n", strFile.c_str());
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
   printf("DBFlush(%s)%s ended %15" PRId64 "ms\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started", GetTimeMillis() - nStart);
        if (fShutdown)
        {
            char** listp;
            if (mapFileUseCount.empty())
            {
                dbenv.log_archive(&listp, DB_ARCH_REMOVE);
                Close();
            }
        }
    }
}

//
// SQLite helpers (new-format wallets)
//

static const char* WALLET_SQLITE_SCHEMA =
    "CREATE TABLE IF NOT EXISTS main ("
    "  key BLOB PRIMARY KEY NOT NULL,"
    "  value BLOB NOT NULL"
    ") WITHOUT ROWID;";

static bool SqliteExec(sqlite3* db, const char* sql)
{
    char* errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK)
    {
        printf("SQLite error: %s\n", errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}

static sqlite3* OpenSqliteWallet(const std::filesystem::path& pathFile, bool fCreate)
{
    int flags = SQLITE_OPEN_READWRITE | (fCreate ? SQLITE_OPEN_CREATE : 0);
    sqlite3* db = NULL;
    int rc = sqlite3_open_v2(pathFile.string().c_str(), &db, flags, NULL);
    if (rc != SQLITE_OK)
    {
        printf("CDB() : sqlite3_open_v2 failed: %s\n", db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db)
            sqlite3_close(db);
        return NULL;
    }

    // secure_delete makes erased rows overwrite their old content with zeros
    // immediately, instead of leaving it in the file's free space -- this is
    // what CDB::Rewrite()'s BDB-specific "purge unencrypted key slack space"
    // dance exists to work around, so SQLite wallets don't need that dance.
    if (!SqliteExec(db, "PRAGMA secure_delete = ON;") ||
        !SqliteExec(db, "PRAGMA synchronous = FULL;") ||
        !SqliteExec(db, WALLET_SQLITE_SCHEMA))
    {
        sqlite3_close(db);
        return NULL;
    }

    return db;
}

//
// CDB
//

CDB::CDB(const char *pszFile, const char* pszMode) :
        format(WalletDBFormat::SQLITE), pdb(NULL), activeTxn(NULL), psqlite(NULL), fSqliteTxnActive(false)
{
    if (pszFile == NULL)
        return;

    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    bool fCreate = strchr(pszMode, 'c');
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    strFile = pszFile;
    std::filesystem::path pathFile = GetDataDir() / pszFile;
    format = DetectWalletDBFormat(pathFile);

    if (format == WalletDBFormat::SQLITE)
    {
        psqlite = OpenSqliteWallet(pathFile, fCreate);
        if (!psqlite)
        {
            strFile = "";
            throw runtime_error(strprintf("CDB() : can't open database file %s (sqlite)", pszFile));
        }

        if (fCreate && !Exists(string("version")))
        {
            bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(CLIENT_VERSION);
            fReadOnly = fTmp;
        }
        return;
    }

    // Berkeley DB (legacy wallet) path
    int ret;
    {
    LOCK(bitdb.cs_db);
    if (!bitdb.Open(GetDataDir()))
          throw runtime_error("env open failed");

        ++bitdb.mapFileUseCount[strFile];
        pdb = bitdb.mapDb[strFile];
        if (pdb == NULL)
        {
            pdb = new Db(&bitdb.dbenv, 0);

            bool fMockDb = bitdb.IsMock();
            if (fMockDb)
            {
                DbMpoolFile*mpf = pdb->get_mpf();
                ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0)
                    throw runtime_error(strprintf("CDB() : failed to configure for no temp file backing for database %s", pszFile));
            }

            ret = pdb->open(NULL,      // Txn pointer
                            fMockDb ? NULL : pszFile,   // Filename
                            "main",    // Logical db name
                            DB_BTREE,  // Database type
                            nFlags,    // Flags
                            0);

            if (ret != 0)
            {
                delete pdb;
                pdb = NULL;
                    --bitdb.mapFileUseCount[strFile];
                strFile = "";
                throw runtime_error(strprintf("CDB() : can't open database file %s, error %d", pszFile, ret));
            }

            if (fCreate && !Exists(string("version")))
            {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(CLIENT_VERSION);
                fReadOnly = fTmp;
            }

            bitdb.mapDb[strFile] = pdb;
        }
    }
}

void CDB::Close()
{
    if (activeTxn)
        activeTxn->abort();
    activeTxn = NULL;

    if (psqlite)
    {
        if (fSqliteTxnActive)
            SqliteExec(psqlite, "ROLLBACK;");
        fSqliteTxnActive = false;
        sqlite3_close(psqlite);
        psqlite = NULL;
        return;
    }

    if (!pdb)
        return;
    pdb = NULL;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;

    bitdb.dbenv.txn_checkpoint(nMinutes ? GetArg("-dblogsize", 100)*1024 : 0, nMinutes, 0);

    {
        LOCK(bitdb.cs_db);
        --bitdb.mapFileUseCount[strFile];
    }
}

bool CDB::ReadRaw(const std::vector<unsigned char>& vchKey, std::vector<unsigned char>& vchValue)
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite)
            return false;
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(psqlite, "SELECT value FROM main WHERE key = ?", -1, &stmt, NULL) != SQLITE_OK)
            return false;
        sqlite3_bind_blob(stmt, 1, vchKey.data(), vchKey.size(), SQLITE_STATIC);
        bool fFound = false;
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            const unsigned char* data = (const unsigned char*)sqlite3_column_blob(stmt, 0);
            int nLen = sqlite3_column_bytes(stmt, 0);
            vchValue.assign(data, data + nLen);
            fFound = true;
        }
        sqlite3_finalize(stmt);
        return fFound;
    }

    if (!pdb)
        return false;

    Dbt datKey((void*)vchKey.data(), vchKey.size());
    Dbt datValue;
    datValue.set_flags(DB_DBT_MALLOC);
    int ret = pdb->get(activeTxn, &datKey, &datValue, 0);
    if (datValue.get_data() == NULL)
        return false;

    vchValue.assign((unsigned char*)datValue.get_data(), (unsigned char*)datValue.get_data() + datValue.get_size());
    memset(datValue.get_data(), 0, datValue.get_size());
    free(datValue.get_data());
    return (ret == 0);
}

bool CDB::WriteRaw(const std::vector<unsigned char>& vchKey, const std::vector<unsigned char>& vchValue, bool fOverwrite)
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite)
            return false;
        const char* sql = fOverwrite
            ? "INSERT INTO main(key, value) VALUES(?, ?)"
              " ON CONFLICT(key) DO UPDATE SET value=excluded.value"
            : "INSERT OR IGNORE INTO main(key, value) VALUES(?, ?)";
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(psqlite, sql, -1, &stmt, NULL) != SQLITE_OK)
            return false;
        sqlite3_bind_blob(stmt, 1, vchKey.data(), vchKey.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, vchValue.data(), vchValue.size(), SQLITE_STATIC);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE)
            return false;
        // Match BDB's DB_NOOVERWRITE: fail (rather than silently no-op) if
        // the key already existed and the caller asked not to overwrite it.
        if (!fOverwrite && sqlite3_changes(psqlite) == 0)
            return false;
        return true;
    }

    if (!pdb)
        return false;

    Dbt datKey((void*)vchKey.data(), vchKey.size());
    Dbt datValue((void*)vchValue.data(), vchValue.size());
    int ret = pdb->put(activeTxn, &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));
    return (ret == 0);
}

bool CDB::EraseRaw(const std::vector<unsigned char>& vchKey)
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite)
            return false;
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(psqlite, "DELETE FROM main WHERE key = ?", -1, &stmt, NULL) != SQLITE_OK)
            return false;
        sqlite3_bind_blob(stmt, 1, vchKey.data(), vchKey.size(), SQLITE_STATIC);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return (rc == SQLITE_DONE);
    }

    if (!pdb)
        return false;

    Dbt datKey((void*)vchKey.data(), vchKey.size());
    int ret = pdb->del(activeTxn, &datKey, 0);
    return (ret == 0 || ret == DB_NOTFOUND);
}

bool CDB::ExistsRaw(const std::vector<unsigned char>& vchKey)
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite)
            return false;
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(psqlite, "SELECT 1 FROM main WHERE key = ?", -1, &stmt, NULL) != SQLITE_OK)
            return false;
        sqlite3_bind_blob(stmt, 1, vchKey.data(), vchKey.size(), SQLITE_STATIC);
        bool fFound = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);
        return fFound;
    }

    if (!pdb)
        return false;

    Dbt datKey((void*)vchKey.data(), vchKey.size());
    int ret = pdb->exists(activeTxn, &datKey, 0);
    return (ret == 0);
}

CDBCursor* CDB::GetCursor()
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite)
            return NULL;
        CDBCursor* pcursor = new CDBCursor();
        // key >= x'' (empty blob) matches every row, giving a plain
        // ascending full-table scan; a later seek re-prepares this same
        // statement bound to a real prefix (see ReadAtCursor).
        if (sqlite3_prepare_v2(psqlite, "SELECT key, value FROM main WHERE key >= ? ORDER BY key", -1, &pcursor->pstmt, NULL) != SQLITE_OK)
        {
            delete pcursor;
            return NULL;
        }
        sqlite3_bind_blob(pcursor->pstmt, 1, "", 0, SQLITE_STATIC);
        return pcursor;
    }

    if (!pdb)
        return NULL;
    Dbc* pdbc = NULL;
    int ret = pdb->cursor(NULL, &pdbc, 0);
    if (ret != 0)
        return NULL;
    CDBCursor* pcursor = new CDBCursor();
    pcursor->pdbc = pdbc;
    return pcursor;
}

int CDB::ReadAtCursor(CDBCursor* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags)
{
    if (!pcursor)
        return 99999;

    if (format == WalletDBFormat::SQLITE)
    {
        if (fFlags == DB_SET_RANGE)
        {
            // Re-prepare the same scan, seeking forward to the given prefix.
            std::vector<unsigned char> vchSeek(ssKey.begin(), ssKey.end());
            sqlite3_finalize(pcursor->pstmt);
            pcursor->pstmt = NULL;
            if (sqlite3_prepare_v2(psqlite, "SELECT key, value FROM main WHERE key >= ? ORDER BY key", -1, &pcursor->pstmt, NULL) != SQLITE_OK)
                return 99999;
            sqlite3_bind_blob(pcursor->pstmt, 1, vchSeek.empty() ? "" : (const void*)vchSeek.data(), vchSeek.size(), SQLITE_TRANSIENT);
        }

        int rc = sqlite3_step(pcursor->pstmt);
        if (rc == SQLITE_DONE)
            return DB_NOTFOUND;
        if (rc != SQLITE_ROW)
            return 99999;

        const unsigned char* pKey = (const unsigned char*)sqlite3_column_blob(pcursor->pstmt, 0);
        int nKeyLen = sqlite3_column_bytes(pcursor->pstmt, 0);
        const unsigned char* pValue = (const unsigned char*)sqlite3_column_blob(pcursor->pstmt, 1);
        int nValueLen = sqlite3_column_bytes(pcursor->pstmt, 1);

        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((const char*)pKey, nKeyLen);
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((const char*)pValue, nValueLen);
        return 0;
    }

    // Berkeley DB cursor
    Dbt datKey;
    if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
    {
        datKey.set_data(&ssKey[0]);
        datKey.set_size(ssKey.size());
    }
    Dbt datValue;
    if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
    {
        datValue.set_data(&ssValue[0]);
        datValue.set_size(ssValue.size());
    }
    datKey.set_flags(DB_DBT_MALLOC);
    datValue.set_flags(DB_DBT_MALLOC);
    int ret = pcursor->pdbc->get(&datKey, &datValue, fFlags);
    if (ret != 0)
        return ret;
    else if (datKey.get_data() == NULL || datValue.get_data() == NULL)
        return 99999;

    // Convert to streams
    ssKey.SetType(SER_DISK);
    ssKey.clear();
    ssKey.write((char*)datKey.get_data(), datKey.get_size());
    ssValue.SetType(SER_DISK);
    ssValue.clear();
    ssValue.write((char*)datValue.get_data(), datValue.get_size());

    // Clear and free memory
    memset(datKey.get_data(), 0, datKey.get_size());
    memset(datValue.get_data(), 0, datValue.get_size());
    free(datKey.get_data());
    free(datValue.get_data());
    return 0;
}

bool CDB::TxnBegin()
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite || fSqliteTxnActive)
            return false;
        if (!SqliteExec(psqlite, "BEGIN TRANSACTION;"))
            return false;
        fSqliteTxnActive = true;
        return true;
    }

    if (!pdb || activeTxn)
        return false;
    DbTxn* ptxn = bitdb.TxnBegin();
    if (!ptxn)
        return false;
    activeTxn = ptxn;
    return true;
}

bool CDB::TxnCommit()
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite || !fSqliteTxnActive)
            return false;
        bool fOk = SqliteExec(psqlite, "COMMIT;");
        fSqliteTxnActive = false;
        return fOk;
    }

    if (!pdb || !activeTxn)
        return false;
    int ret = activeTxn->commit(0);
    activeTxn = NULL;
    return (ret == 0);
}

bool CDB::TxnAbort()
{
    if (format == WalletDBFormat::SQLITE)
    {
        if (!psqlite || !fSqliteTxnActive)
            return false;
        bool fOk = SqliteExec(psqlite, "ROLLBACK;");
        fSqliteTxnActive = false;
        return fOk;
    }

    if (!pdb || !activeTxn)
        return false;
    int ret = activeTxn->abort();
    activeTxn = NULL;
    return (ret == 0);
}

static bool RewriteSqlite(const std::filesystem::path& pathFile, const char* pszSkip)
{
    sqlite3* db = OpenSqliteWallet(pathFile, false);
    if (!db)
        return false;

    std::filesystem::path pathTmp = pathFile;
    pathTmp += ".rewrite";
    std::filesystem::remove(pathTmp);

    sqlite3* dbCopy = OpenSqliteWallet(pathTmp, true);
    if (!dbCopy)
    {
        sqlite3_close(db);
        return false;
    }

    bool fSuccess = true;
    sqlite3_stmt* pstmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT key, value FROM main ORDER BY key", -1, &pstmt, NULL) == SQLITE_OK)
    {
        size_t nSkipLen = pszSkip ? strlen(pszSkip) : 0;
        while (fSuccess)
        {
            int rc = sqlite3_step(pstmt);
            if (rc == SQLITE_DONE)
                break;
            if (rc != SQLITE_ROW)
            {
                fSuccess = false;
                break;
            }

            const char* pKey = (const char*)sqlite3_column_blob(pstmt, 0);
            int nKeyLen = sqlite3_column_bytes(pstmt, 0);
            if (pszSkip && (size_t)nKeyLen >= nSkipLen && memcmp(pKey, pszSkip, nSkipLen) == 0)
                continue;

            sqlite3_stmt* pins = NULL;
            if (sqlite3_prepare_v2(dbCopy, "INSERT INTO main(key, value) VALUES(?, ?)", -1, &pins, NULL) != SQLITE_OK)
            {
                fSuccess = false;
                break;
            }
            sqlite3_bind_blob(pins, 1, sqlite3_column_blob(pstmt, 0), nKeyLen, SQLITE_TRANSIENT);
            sqlite3_bind_blob(pins, 2, sqlite3_column_blob(pstmt, 1), sqlite3_column_bytes(pstmt, 1), SQLITE_TRANSIENT);
            int ret2 = sqlite3_step(pins);
            sqlite3_finalize(pins);
            if (ret2 != SQLITE_DONE)
                fSuccess = false;
        }
        sqlite3_finalize(pstmt);
    }
    else
        fSuccess = false;

    sqlite3_close(db);
    sqlite3_close(dbCopy);

    if (fSuccess)
    {
        std::error_code ec;
        std::filesystem::remove(pathFile, ec);
        std::filesystem::rename(pathTmp, pathFile, ec);
        fSuccess = !ec;
    }
    else
    {
        std::filesystem::remove(pathTmp);
    }
    return fSuccess;
}

bool CDB::Rewrite(const string& strFile, const char* pszSkip)
{
    std::filesystem::path pathFile = GetDataDir() / strFile;
    if (DetectWalletDBFormat(pathFile) == WalletDBFormat::SQLITE)
    {
        while (!fShutdown)
        {
            {
                LOCK(bitdb.cs_db);
                if (!bitdb.mapFileUseCount.count(strFile) || bitdb.mapFileUseCount[strFile] == 0)
                {
                    printf("Rewriting %s...\n", strFile.c_str());
                    bool fSuccess = RewriteSqlite(pathFile, pszSkip);
                    if (!fSuccess)
                        printf("Rewriting of %s FAILED!\n", strFile.c_str());
                    return fSuccess;
                }
            }
            MilliSleep(100);
        }
        return false;
    }

    while (!fShutdown)
    {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(strFile) || bitdb.mapFileUseCount[strFile] == 0)
            {
                // Flush log data to the dat file
                bitdb.CloseDb(strFile);
                bitdb.CheckpointLSN(strFile);
                bitdb.mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                printf("Rewriting %s...\n", strFile.c_str());
                string strFileRes = strFile + ".rewrite";
                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
                    Db* pdbCopy = new Db(&bitdb.dbenv, 0);

                    int ret = pdbCopy->open(NULL,                 // Txn pointer
                                            strFileRes.c_str(),   // Filename
                                            "main",    // Logical db name
                                            DB_BTREE,  // Database type
                                            DB_CREATE,    // Flags
                                            0);
                    if (ret > 0)
                    {
                        printf("Cannot create database file %s\n", strFileRes.c_str());
                        fSuccess = false;
                    }

                    CDBCursor* pcursor = db.GetCursor();
                    if (pcursor)
                        while (fSuccess)
                        {
                            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                            int ret = db.ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
                            if (ret == DB_NOTFOUND)
                            {
                                delete pcursor;
                                break;
                            }
                            else if (ret != 0)
                            {
                                delete pcursor;
                                fSuccess = false;
                                break;
                            }
                            if (pszSkip &&
                                strncmp(&ssKey[0], pszSkip, std::min(ssKey.size(), strlen(pszSkip))) == 0)
                                continue;
                            if (strncmp(&ssKey[0], "\x07version", 8) == 0)
                            {
                                // Update version:
                                ssValue.clear();
                                ssValue << CLIENT_VERSION;
                            }
                            Dbt datKey(&ssKey[0], ssKey.size());
                            Dbt datValue(&ssValue[0], ssValue.size());
                            int ret2 = pdbCopy->put(NULL, &datKey, &datValue, DB_NOOVERWRITE);
                            if (ret2 > 0)
                                fSuccess = false;
                        }
                    if (fSuccess)
                    {
                        db.Close();
                        bitdb.CloseDb(strFile);
                        if (pdbCopy->close(0))
                            fSuccess = false;
                        delete pdbCopy;
                    }
                }
                if (fSuccess)
                {
                    Db dbA(&bitdb.dbenv, 0);
                    if (dbA.remove(strFile.c_str(), NULL, 0))
                        fSuccess = false;
                    Db dbB(&bitdb.dbenv, 0);
                    if (dbB.rename(strFileRes.c_str(), NULL, strFile.c_str(), 0))
                        fSuccess = false;
                }
                if (!fSuccess)
                    printf("Rewriting of %s FAILED!\n", strFileRes.c_str());
                return fSuccess;
            }
        }
        MilliSleep(100);
    }
    return false;
}

//
// Migration (BDB -> SQLite)
//

bool CDB::MigrateBDBToSQLite(const std::string& strWalletFile, std::string& strError)
{
    std::filesystem::path pathFile = GetDataDir() / strWalletFile;

    if (DetectWalletDBFormat(pathFile) != WalletDBFormat::BDB)
    {
        strError = "wallet is already SQLite format, nothing to migrate";
        return false;
    }

    {
        LOCK(bitdb.cs_db);
        if (bitdb.mapFileUseCount.count(strWalletFile) && bitdb.mapFileUseCount[strWalletFile] != 0)
        {
            strError = "wallet file is currently in use";
            return false;
        }
    }

    std::filesystem::path pathTmp = pathFile;
    pathTmp += ".sqlite-migrate";
    std::filesystem::remove(pathTmp);

    sqlite3* dbNew = OpenSqliteWallet(pathTmp, true);
    if (!dbNew)
    {
        strError = "failed to create new SQLite wallet file";
        return false;
    }

    bool fSuccess = true;
    unsigned int nRecords = 0;
    {
        CDB db(strWalletFile.c_str(), "r");
        CDBCursor* pcursor = db.GetCursor();
        if (!pcursor)
        {
            strError = "cannot open BDB cursor";
            fSuccess = false;
        }
        else
        {
            while (fSuccess)
            {
                CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                int ret = db.ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
                if (ret == DB_NOTFOUND)
                    break;
                if (ret != 0)
                {
                    strError = "error reading BDB wallet during migration";
                    fSuccess = false;
                    break;
                }

                sqlite3_stmt* pins = NULL;
                if (sqlite3_prepare_v2(dbNew, "INSERT INTO main(key, value) VALUES(?, ?)", -1, &pins, NULL) != SQLITE_OK)
                {
                    strError = "failed to prepare insert during migration";
                    fSuccess = false;
                    break;
                }
                sqlite3_bind_blob(pins, 1, &ssKey[0], ssKey.size(), SQLITE_TRANSIENT);
                sqlite3_bind_blob(pins, 2, &ssValue[0], ssValue.size(), SQLITE_TRANSIENT);
                int ret2 = sqlite3_step(pins);
                sqlite3_finalize(pins);
                if (ret2 != SQLITE_DONE)
                {
                    strError = "failed to write record during migration";
                    fSuccess = false;
                    break;
                }
                nRecords++;
            }
            delete pcursor;
        }
        db.Close();
    }

    sqlite3_close(dbNew);

    if (!fSuccess)
    {
        std::filesystem::remove(pathTmp);
        return false;
    }

    // Preserve the original BDB file under a backup name, then move the new
    // SQLite file into place.
    std::filesystem::path pathBak = pathFile;
    pathBak += strprintf(".%" PRId64 ".bdb.bak", GetTime());

    {
        LOCK(bitdb.cs_db);
        bitdb.CloseDb(strWalletFile);
    }

    std::error_code ec;
    std::filesystem::rename(pathFile, pathBak, ec);
    if (ec)
    {
        strError = "failed to back up original BDB wallet file";
        std::filesystem::remove(pathTmp);
        return false;
    }
    std::filesystem::rename(pathTmp, pathFile, ec);
    if (ec)
    {
        // Restore the original so the user isn't left without any wallet file.
        std::error_code ec2;
        std::filesystem::rename(pathBak, pathFile, ec2);
        strError = "failed to move migrated SQLite wallet into place";
        return false;
    }

    printf("Migrated wallet %s from Berkeley DB to SQLite (%u records); original preserved as %s\n",
           strWalletFile.c_str(), nRecords, pathBak.string().c_str());
    return true;
}

//
// CAddrDB
//

CAddrDB::CAddrDB()
{
    pathAddr = GetDataDir() / "peers.dat";
}

bool CAddrDB::Write(const CAddrMan& addr)
{
 // Generate random temporary filename
 unsigned short randv = 0;
 GetRandBytes((unsigned char *)&randv, sizeof(randv));
 std::string tmpfn = strprintf("peers.dat.%04x", randv);

 // serialize addresses, checksum data up to that point, then append csum
 CDataStream ssPeers(SER_DISK, CLIENT_VERSION);
 ssPeers << FLATDATA(pchMessageStart);
 ssPeers << addr;
 uint256 hash = Hash(ssPeers.begin(), ssPeers.end());
 ssPeers << hash;

 // open temp output file, and associate with CAutoFile
 std::filesystem::path pathTmp = GetDataDir() / tmpfn;
 FILE *file = fopen(pathTmp.string().c_str(), "wb");
 CAutoFile fileout = CAutoFile(file, SER_DISK, CLIENT_VERSION);
 if (!fileout)
 return error("CAddrman::Write() : open failed");

 // Write and commit header, data
 try {
 fileout << ssPeers;
          }

    // Read pre-0.6 addr records

catch (std::exception &e) {
 return error("CAddrman::Write() : I/O error");
 }
 FileCommit(fileout);
 fileout.fclose();

// replace existing peers.dat, if any, with new peers.dat.XXXX
 if (!RenameOver(pathTmp, pathAddr))
 return error("CAddrman::Write() : Rename-into-place failed");

 return true;
}

bool CAddrDB::Read(CAddrMan& addr)
{
 // open input file, and associate with CAutoFile
 FILE *file = fopen(pathAddr.string().c_str(), "rb");
 CAutoFile filein = CAutoFile(file, SER_DISK, CLIENT_VERSION);
 if (!filein)
 return error("CAddrman::Read() : open failed");

 // use file size to size memory buffer
 int fileSize = GetFilesize(filein);
 int dataSize = fileSize - sizeof(uint256);
 //Don't try to resize to a negative number if file is small
 if ( dataSize < 0 ) dataSize = 0;
 vector<unsigned char> vchData;
 vchData.resize(dataSize);
 uint256 hashIn;

 // read data and checksum from file
 try {
 filein.read((char *)&vchData[0], dataSize);
 filein >> hashIn;
    }
 catch (std::exception &e) {
 return error("CAddrman::Read() 2 : I/O error or stream data corrupted");
 }
 filein.fclose();

 CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

 // verify stored checksum matches input data
 uint256 hashTmp = Hash(ssPeers.begin(), ssPeers.end());
 if (hashIn != hashTmp)
 return error("CAddrman::Read() : checksum mismatch; data corrupted");

  // de-serialize address data
 unsigned char pchMsgTmp[4];
 try {
        // de-serialize file header (pchMessageStart magic number) and
 ssPeers >> FLATDATA(pchMsgTmp);

 // finally, verify the network matches ours
 if (memcmp(pchMsgTmp, pchMessageStart, sizeof(pchMsgTmp)))
 return error("CAddrman::Read() : invalid network magic number");

  // de-serialize address data into one CAddrMan object
 ssPeers >> addr;
 }
 catch (std::exception &e) {
 return error("CAddrman::Read() : I/O error or stream data corrupted");
 }

 return true;
}
