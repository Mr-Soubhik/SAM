#include "../src/watcher.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>
#include <filesystem>

using namespace std;

int main() {
    SAM::Watcher watcher;
    cout << "[TEST] Testing Kernel Event Capture (inotify/epoll)...\n";

    string test_dir = "/tmp/sam_test";
    filesystem::create_directory(test_dir);
    watcher.add_watch(test_dir);

    bool event_seen = false;
    watcher.start([&](const SAM::FileEvent& e) {
        cout << "  - Captured event at: " << e.path << "\n";
        event_seen = true;
    });

    ofstream test_file(test_dir + "/new_config.cfg");
    test_file << "test data";
    test_file.close();

    this_thread::sleep_for(chrono::milliseconds(200));
    watcher.stop();

    if (event_seen) {
        cout << "[PASS] Watcher successfully captured real-time event.\n";
    } else {
        cerr << "[FAIL] Watcher missed the event.\n";
        return 1;
    }

    filesystem::remove_all(test_dir);
    return 0;
}