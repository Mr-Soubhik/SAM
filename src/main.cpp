#include "ledger.hpp"
#include "scanner.hpp"
#include "purge.hpp"
#include "watcher.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>

using namespace std;
namespace fs = std::filesystem;

// menu for user
void showHelp() {
    cout << "SAM - System Audit Manager\n";
    cout << "Commands:\n";
    cout << "  install <cmd>   - install and track\n";
    cout << "  remove <app>    - uninstall app\n";
    cout << "  scan            - run system audit\n";
    cout << "  status          - show system rot\n";
    cout << "  watch           - monitor files\n";
    cout << "  help            - show this\n";
    cout << "  quit            - exit\n";
}

// track install
void trackInstall(SAM::Ledger& db, vector<string> args) {
    if (args.empty()) {
        cout << "Error: need a command.\n";
        return;
    }

    SAM::Watcher w;
    string homeDir = "/tmp";
    if (getenv("HOME") != NULL) {
        homeDir = getenv("HOME");
    }
    w.add_watch(homeDir);

    cout << "Starting tracking...\n";

    pid_t pid = fork();
    if (pid == 0) {
        // child process
        vector<char*> c_args;
        for (int i = 0; i < args.size(); i++) {
            c_args.push_back((char*)args[i].c_str());
        }
        c_args.push_back(NULL);
        execvp(c_args[0], c_args.data());
        exit(1);
    } else if (pid > 0) {
        // parent process
        w.start([&](const SAM::FileEvent& ev) {
            cout << " [TRACKED] " << ev.path << "\n";
        }, pid);

        int stat;
        waitpid(pid, &stat, 0);
        w.stop();
        cout << "Done tracking.\n";
        db.add_audit_entry("INSTALL", args[0], "Tracked install done.");
    }
}

// run the commands
bool runCommand(SAM::Ledger& db, vector<string> args) {
    if (args.size() == 0) return true;

    string cmd = args[0];
    string home = "/tmp";
    if (getenv("HOME") != NULL) {
        home = getenv("HOME");
    }

    if (cmd == "install") {
        vector<string> installArgs;
        for (int i = 1; i < args.size(); i++) {
            installArgs.push_back(args[i]);
        }
        trackInstall(db, installArgs);
    }
    else if (cmd == "remove") {
        if (args.size() < 2) {
            cout << "Usage: remove <app>\n";
            return true;
        }
        string appName = args[1];
        cout << "Removing " << appName << "...\n";
        
        SAM::PurgeConfig pConf;
        SAM::PurgeEngine pe(pConf);
        SAM::AppManifest m;
        m.app_name = appName;
        m.owned_paths.push_back(home + "/.config/" + appName);
        m.owned_paths.push_back(home + "/.cache/" + appName);
        
        auto res = pe.remove(m);
        if (res.success) {
            db.add_audit_entry("REMOVE", appName, "User removed app.");
        }
    }
    else if (cmd == "scan") {
        SAM::ScanConfig sc;
        SAM::HomeScanner scanner(db, sc); 
        cout << "Scanning..." << endl;
        scanner.scan();
        db.add_audit_entry("SCAN", "System", "Audit done.");
    }
    else if (cmd == "status") {
        db.display_tracked_apps();
        db.show_recoverable_size();
        bool isOk = db.verify_audit_chain();
        if (isOk) {
            cout << "Audit is VALID\n";
        } else {
            cout << "Audit is COMPROMISED\n";
        }
    }
    else if (cmd == "watch") {
        SAM::Watcher w;
        w.add_watch(home);
        cout << "Watcher active. Press ENTER to stop.\n";
        w.start([](const SAM::FileEvent& ev) {
            cout << ev.to_string() << endl;
        });
        cin.get(); 
        w.stop();
    }
    else if (cmd == "help") {
        showHelp();
    }
    else if (cmd == "exit" || cmd == "quit") {
        return false;
    }
    else {
        cout << "Unknown command. Type help.\n";
    }
    return true;
}

int main(int argc, char* argv[]) {
    // setup db path
    string home = "/tmp";
    if (getenv("HOME") != NULL) {
        home = getenv("HOME");
    }
    string dbPath = home + "/.sam/ledger.db";
    fs::create_directories(fs::path(dbPath).parent_path());
    
    try {
        SAM::Ledger db(dbPath);

        // REPL loop
        if (argc < 2) {
            showHelp();
            string line;
            while (true) {
                cout << "\nsam > ";
                if (!getline(cin, line)) break;
                
                stringstream ss(line);
                vector<string> args;
                string w;
                while (ss >> w) {
                    args.push_back(w);
                }

                if (!runCommand(db, args)) break;
            }
            return 0;
        }

        // one shot command
        vector<string> args;
        for (int i = 1; i < argc; i++) {
            args.push_back(argv[i]);
        }
        runCommand(db, args);

    } catch (exception& e) {
        cout << "ERROR: " << e.what() << endl;
        return 1;
    }

    return 0;
}