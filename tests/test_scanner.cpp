#include "../src/scanner.hpp"
#include "../src/ledger.hpp"
#include <cassert>
#include <iostream>

using namespace std;

int main() {
    SAM::Ledger ledger("test_scanner.db");
    SAM::Scanner scanner(ledger);

    cout << "[TEST] Running Ghost Detection Logic...\n";

    ledger.create_app("old-app", "snap");
    ledger.mark_removed("old-app"); 
    
    ledger.add_file_to_app("old-app", "/home/user/.config/old-app/settings.json", 0.95);

    auto ghosts = scanner.find_ghosts();
    
    assert(!ghosts.empty());
    assert(ghosts[0].app_name == "old-app");

    cout << "[PASS] Ghost Detector correctly identified orphaned files.\n";
    return 0;
}