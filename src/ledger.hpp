#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <mutex>

namespace SAM {

// wrapper for sqlite statement
struct Stmt {
    sqlite3_stmt* ptr = nullptr;
    ~Stmt() { if (ptr) sqlite3_finalize(ptr); }
    operator sqlite3_stmt*() { return ptr; }
};

// app record in database
struct LedgerAppRecord {
    int id;
    std::string name;
    std::string version;
    std::string install_method;
    std::string status;
    long long installed_at;
    long long total_bytes;
    int file_count;
};

// sqlite ledger database class
class Ledger {
public:
    Ledger(const std::string& db_path);
    ~Ledger();

    bool initialize_schema();
    bool add_or_update_app(const LedgerAppRecord& app);
    bool record_file(int app_id, const std::string& path, long long size, const std::string& confidence, const std::string& file_type);
    int  get_app_id(const std::string& name);

    void begin_transaction();
    void commit();
    void rollback();
    
    void add_audit_entry(const std::string& action, const std::string& app_name, const std::string& detail);
    bool verify_audit_chain();

    std::vector<LedgerAppRecord> get_apps_by_status(const std::string& status);
    std::vector<LedgerAppRecord> get_all_apps();
    void update_app_totals(int app_id);
    void remove_apps_by_source(const std::string& source);
    
    void display_tracked_apps();
    void show_recoverable_size();

private:
    sqlite3* db = nullptr;
    mutable std::mutex db_mutex_;

    std::string calculate_sha256(const std::string& data);
    std::string get_last_audit_hash();
    
    void execute_query(const std::string& sql);
};

} // namespace SAM
