#include "../src/purge.hpp"
#include "../src/ledger.hpp"
#include <cassert>
#include <iostream>
#include <cstdlib>

using namespace std;

int main() {
    SAM::Ledger ledger("test_purge.db");
    SAM::PurgeEngine purge(ledger);
    string home = getenv("HOME");

    cout << "[TEST] Running Safety Gate Stress Test...\n";

    // Gate 1: system path check
    assert(purge.run_gates("/etc/passwd") == SAM::GateResult::SystemPath);
    cout << "  - Gate 1: System Path Blocked (OK)\n";

    // Gate 2: safe zone check
    string desktop_path = home + "/Desktop/important_file.txt";
    assert(purge.run_gates(desktop_path) == SAM::GateResult::SafeZone);
    cout << "  - Gate 2: Desktop Safe Zone Protected (OK)\n";

    cout << "[PASS] Purge Engine prevented all unsafe deletions.\n";
    return 0;
}