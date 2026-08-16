#include "../src/ledger.hpp"
#include <cassert>
#include <iostream>
#include <filesystem>

using namespace std;

int main() {
    cout << "[TEST] Initializing Ledger Sandbox...\n";
    SAM::Ledger ledger("test_sam.db");
    ledger.init_schema();

    cout << "  - Testing App Tracking...\n";
    int app_id = ledger.create_app("test-vlc", "apt");
    assert(app_id > 0);

    cout << "  - Testing SHA-256 Audit Chain...\n";
    ledger.add_audit_entry("INSTALL", "/home/user/.config/vlc", "Initial Tracking");
    ledger.add_audit_entry("PURGE", "/home/user/.config/vlc", "Cleanup Simulation");

    bool is_valid = ledger.verify_audit_chain();
    assert(is_valid == true);

    cout << "[PASS] Ledger and Integrity logic verified.\n";
    filesystem::remove("test_sam.db");
    return 0;
}