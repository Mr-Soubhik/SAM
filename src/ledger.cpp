#include "ledger.hpp"
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <chrono>

using namespace std;

namespace SAM {

Ledger::Ledger(const string& db_path) {
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
        throw runtime_error("Failed to open SAM Ledger database");
    }

    // basic optimizations
    execute_query("PRAGMA journal_mode = WAL;");
    execute_query("PRAGMA synchronous = NORMAL;");
    execute_query("PRAGMA foreign_keys = ON;");
    
    initialize_schema();
}

Ledger::~Ledger() {
    if (db) {
        sqlite3_close(db);
    }
}

void Ledger::execute_query(const string& sql) {
    db_mutex_.lock();
    char* err = NULL;
    sqlite3_exec(db, sql.c_str(), NULL, NULL, &err);
    if (err) {
        cout << "SQL Error: " << err << endl;
        sqlite3_free(err);
    }
    db_mutex_.unlock();
}

bool Ledger::initialize_schema() {
    // big sql string for creating tables
    string schema = R"(
        CREATE TABLE IF NOT EXISTS apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            version TEXT NOT NULL DEFAULT '',
            install_method TEXT NOT NULL DEFAULT 'unknown',
            status TEXT NOT NULL DEFAULT 'active',
            installed_at INTEGER NOT NULL,
            total_bytes INTEGER DEFAULT 0,
            file_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            size_bytes INTEGER DEFAULT 0,
            confidence TEXT DEFAULT 'confirmed',
            file_type TEXT DEFAULT 'unknown',
            UNIQUE(app_id, path)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            app_name TEXT NOT NULL,
            detail TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );
    )";
    execute_query(schema);
    return true;
}

bool Ledger::add_or_update_app(const LedgerAppRecord& app) {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "INSERT INTO apps (name, version, install_method, installed_at) "
                      "VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                      "version=excluded.version, status='active';";
    
    Stmt stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL);
    sqlite3_bind_text(stmt, 1, app.name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, app.version.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, app.install_method.c_str(), -1, SQLITE_STATIC);
    
    long long now_time = chrono::system_clock::to_time_t(chrono::system_clock::now());
    sqlite3_bind_int64(stmt, 4, now_time);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return true;
    }
    return false;
}

string Ledger::calculate_sha256(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.size(), hash);
    
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void Ledger::add_audit_entry(const string& action, const string& app_name, const string& detail) {
    lock_guard<mutex> lock(db_mutex_);
    
    string prev_hash = get_last_audit_hash(); 
    long long ts = chrono::system_clock::to_time_t(chrono::system_clock::now());
    
    string content = action + app_name + detail + to_string(ts) + prev_hash;
    string current_hash = calculate_sha256(content);

    const char* sql = "INSERT INTO audit_log (action, app_name, detail, timestamp, prev_hash, entry_hash) "
                      "VALUES (?, ?, ?, ?, ?, ?);";
    
    Stmt stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL);
    sqlite3_bind_text(stmt, 1, action.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, app_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, detail.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, ts);
    sqlite3_bind_text(stmt, 5, prev_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, current_hash.c_str(), -1, SQLITE_STATIC);

    sqlite3_step(stmt);
}

string Ledger::get_last_audit_hash() {
    const char* sql = "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1;";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* h = (const char*)sqlite3_column_text(stmt, 0);
            if (h != NULL) return h;
        }
    }
    return "GENESIS_BLOCK";
}

void Ledger::update_app_totals(int app_id) {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "UPDATE apps SET total_bytes = (SELECT IFNULL(SUM(size_bytes),0) FROM files WHERE app_id = ?), "
                      "file_count = (SELECT COUNT(*) FROM files WHERE app_id = ?) WHERE id = ?;";
    Stmt stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL);
    sqlite3_bind_int(stmt, 1, app_id);
    sqlite3_bind_int(stmt, 2, app_id);
    sqlite3_bind_int(stmt, 3, app_id);
    sqlite3_step(stmt);
}

void Ledger::remove_apps_by_source(const string& source) {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "DELETE FROM apps WHERE install_method = ?;";
    Stmt stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL);
    sqlite3_bind_text(stmt, 1, source.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
}

void Ledger::display_tracked_apps() {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "SELECT id, name, version, status, total_bytes FROM apps ORDER BY total_bytes DESC;";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) == SQLITE_OK) {
        cout << "\n--- Tracked Applications ---\n";
        cout << left << setw(20) << "Name" 
             << setw(15) << "Version" 
             << setw(10) << "Status" 
             << setw(12) << "Total (MB)"
             << "Breakdown (Config/Cache/Data)\n";
        
        // print a line
        for(int i=0; i<100; i++) cout << "-";
        cout << "\n";
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int app_id = sqlite3_column_int(stmt, 0);
            string name = (const char*)sqlite3_column_text(stmt, 1);
            string version = (const char*)sqlite3_column_text(stmt, 2);
            string status = (const char*)sqlite3_column_text(stmt, 3);
            long long bytes = sqlite3_column_int64(stmt, 4);
            
            double mb = (double)bytes / (1024.0 * 1024.0);
            
            long long config_b = 0, cache_b = 0, data_b = 0;
            const char* b_sql = "SELECT file_type, SUM(size_bytes) FROM files WHERE app_id = ? GROUP BY file_type;";
            Stmt b_stmt;
            if (sqlite3_prepare_v2(db, b_sql, -1, &b_stmt.ptr, NULL) == SQLITE_OK) {
                sqlite3_bind_int(b_stmt, 1, app_id);
                while (sqlite3_step(b_stmt) == SQLITE_ROW) {
                    const char* type_raw = (const char*)sqlite3_column_text(b_stmt, 0);
                    string type = "unknown";
                    if (type_raw != NULL) {
                        type = type_raw;
                    }
                    long long val = sqlite3_column_int64(b_stmt, 1);
                    
                    if (type == "config") config_b = val;
                    else if (type == "cache") cache_b = val;
                    else if (type == "data") data_b = val;
                }
            }

            // simple math instead of lambda
            double c_mb = (double)config_b / (1024.0 * 1024.0);
            double cache_mb = (double)cache_b / (1024.0 * 1024.0);
            double d_mb = (double)data_b / (1024.0 * 1024.0);

            cout << left << setw(20) << name 
                 << setw(15) << version 
                 << setw(10) << status 
                 << setw(12) << fixed << setprecision(2) << mb
                 << fixed << setprecision(1) 
                 << c_mb << " / " << cache_mb << " / " << d_mb << " MB\n";
        }
    }
}

void Ledger::show_recoverable_size() {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "SELECT SUM(total_bytes) FROM apps WHERE status = 'ghost';";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            long long bytes = sqlite3_column_int64(stmt, 0);
            double mb = (double)bytes / (1024.0 * 1024.0);
            cout << "\nTotal Recoverable Space (Ghost Apps): " 
                 << fixed << setprecision(2) << mb << " MB\n";
        }
    }
}

bool Ledger::record_file(int app_id, const string& path, long long size, const string& confidence, const string& file_type) {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "INSERT INTO files (app_id, path, size_bytes, confidence, file_type) VALUES (?, ?, ?, ?, ?) "
                      "ON CONFLICT(app_id, path) DO UPDATE SET size_bytes=excluded.size_bytes, file_type=excluded.file_type;";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, app_id);
    sqlite3_bind_text(stmt, 2, path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, size);
    sqlite3_bind_text(stmt, 4, confidence.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, file_type.c_str(), -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) return true;
    return false;
}

int Ledger::get_app_id(const string& name) {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "SELECT id FROM apps WHERE name = ?;";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            return sqlite3_column_int(stmt, 0);
        }
    }
    return -1;
}

void Ledger::begin_transaction() {
    execute_query("BEGIN TRANSACTION;");
}

void Ledger::commit() {
    execute_query("COMMIT;");
}

void Ledger::rollback() {
    execute_query("ROLLBACK;");
}

vector<LedgerAppRecord> Ledger::get_apps_by_status(const string& status) {
    lock_guard<mutex> lock(db_mutex_);
    vector<LedgerAppRecord> apps;
    const char* sql = "SELECT id, name, version, install_method, status, installed_at, total_bytes, file_count "
                      "FROM apps WHERE status = ?;";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            LedgerAppRecord r;
            r.id = sqlite3_column_int(stmt, 0);
            r.name = (const char*)sqlite3_column_text(stmt, 1);
            r.version = (const char*)sqlite3_column_text(stmt, 2);
            r.install_method = (const char*)sqlite3_column_text(stmt, 3);
            r.status = (const char*)sqlite3_column_text(stmt, 4);
            r.installed_at = sqlite3_column_int64(stmt, 5);
            r.total_bytes = sqlite3_column_int64(stmt, 6);
            r.file_count = sqlite3_column_int(stmt, 7);
            apps.push_back(r);
        }
    }
    return apps;
}

vector<LedgerAppRecord> Ledger::get_all_apps() {
    lock_guard<mutex> lock(db_mutex_);
    vector<LedgerAppRecord> apps;
    const char* sql = "SELECT id, name, version, install_method, status, installed_at, total_bytes, file_count "
                      "FROM apps ORDER BY total_bytes DESC;";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            LedgerAppRecord r;
            r.id = sqlite3_column_int(stmt, 0);
            r.name = (const char*)sqlite3_column_text(stmt, 1);
            r.version = (const char*)sqlite3_column_text(stmt, 2);
            r.install_method = (const char*)sqlite3_column_text(stmt, 3);
            r.status = (const char*)sqlite3_column_text(stmt, 4);
            r.installed_at = sqlite3_column_int64(stmt, 5);
            r.total_bytes = sqlite3_column_int64(stmt, 6);
            r.file_count = sqlite3_column_int(stmt, 7);
            apps.push_back(r);
        }
    }
    return apps;
}

bool Ledger::verify_audit_chain() {
    lock_guard<mutex> lock(db_mutex_);
    const char* sql = "SELECT action, app_name, detail, timestamp, prev_hash, entry_hash FROM audit_log ORDER BY id ASC;";
    Stmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt.ptr, NULL) != SQLITE_OK) return false;
    
    string expected_prev_hash = "GENESIS_BLOCK";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        string action = (const char*)sqlite3_column_text(stmt, 0);
        string app_name = (const char*)sqlite3_column_text(stmt, 1);
        string detail = (const char*)sqlite3_column_text(stmt, 2);
        long long ts = sqlite3_column_int64(stmt, 3);
        string prev_hash = (const char*)sqlite3_column_text(stmt, 4);
        string entry_hash = (const char*)sqlite3_column_text(stmt, 5);
        
        if (prev_hash != expected_prev_hash) {
            return false;
        }
        
        string content = action + app_name + detail + to_string(ts) + prev_hash;
        if (calculate_sha256(content) != entry_hash) {
            return false;
        }
        
        expected_prev_hash = entry_hash;
    }
    return true;
}

} // namespace SAM