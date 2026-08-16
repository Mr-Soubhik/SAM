#include "purge.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>

using namespace std;

namespace SAM {

// get string for gate result
string gate_result_str(GateResult g) {
    switch (g) {
        case GateResult::Safe:       return "SAFE";
        case GateResult::SystemPath: return "SYSTEM PATH";
        case GateResult::SafeZone:   return "SAFE ZONE";
        case GateResult::Dependency: return "DEPENDENCY";
        case GateResult::LowConf:    return "LOW CONFIDENCE";
        case GateResult::TooNew:     return "TOO NEW";
        case GateResult::NotFound:   return "NOT FOUND";
    }
    return "UNKNOWN";
}

// helper to get home dir
static string get_home() {
    const char* h = getenv("HOME");
    if (h && *h) return h;
    throw runtime_error("$HOME not set");
}

static int64_t now_seconds() {
    return chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t file_mtime_seconds(const string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return 0;
    return (int64_t)st.st_mtime;
}

// format bytes into MB/GB/KB
static string fmt_bytes(int64_t b) {
    if (b >= 1024LL * 1024 * 1024)
        return to_string(b / (1024 * 1024 * 1024)) + " GB";
    if (b >= 1024 * 1024)
        return to_string(b / (1024 * 1024)) + " MB";
    if (b >= 1024)
        return to_string(b / 1024) + " KB";
    return to_string(b) + " B";
}

// terminal colors
static const string RED    = "\033[31m";
static const string GREEN  = "\033[32m";
static const string YELLOW = "\033[33m";
static const string CYAN   = "\033[36m";
static const string BOLD   = "\033[1m";
static const string RESET  = "\033[0m";

PurgeEngine::PurgeEngine(PurgeConfig config)
    : config_(move(config))
    , home_(get_home())
{}

// Gate 1: System path
bool PurgeEngine::starts_with_any_system_prefix(const string& path) const {
    static constexpr const char* PREFIXES[] = {
        "/usr", "/lib", "/lib64", "/bin", "/sbin",
        "/etc", "/var", "/sys", "/proc", "/boot",
        "/run", "/dev", "/snap/bin", "/opt",
        nullptr
    };

    for (int i = 0; PREFIXES[i] != nullptr; ++i) {
        const char* p = PREFIXES[i];
        size_t l = strlen(p);
        if (path.size() >= l &&
            path.compare(0, l, p) == 0 &&
            (path.size() == l || path[l] == '/'))
            return true;
    }
    return false;
}

GateResult PurgeEngine::gate1_system_path(const string& path) const {
    if (starts_with_any_system_prefix(path))
        return GateResult::SystemPath;
    return GateResult::Safe;
}

// Gate 2: Safe zone
GateResult PurgeEngine::gate2_safe_zone(const string& path) const {
    for (auto& zone : config_.safe_zones) {
        string safe = home_ + "/" + zone;
        if (path == safe || path.rfind(safe + "/", 0) == 0)
            return GateResult::SafeZone;
    }
    return GateResult::Safe;
}

// Gate 3: Dependency guard
GateResult PurgeEngine::gate3_dependency(const string& path, const AppManifest& manifest) const {
    for (auto& lib : manifest.shared_libs) {
        if (path == lib || path.rfind(lib, 0) == 0)
            return GateResult::Dependency;
    }
    return GateResult::Safe;
}

// Gate 4: Confidence check
GateResult PurgeEngine::gate4_confidence(const string& confidence) const {
    if (confidence == "inferred")
        return GateResult::LowConf;
    return GateResult::Safe;
}

// Gate 5: Age check
int64_t PurgeEngine::file_age_days(const string& path) const {
    int64_t mtime = file_mtime_seconds(path);
    if (mtime == 0) return 9999;
    return (now_seconds() - mtime) / 86400;
}

GateResult PurgeEngine::gate5_age(const string& path) const {
    if (file_age_days(path) < config_.protect_newer_than_days)
        return GateResult::TooNew;
    return GateResult::Safe;
}

// Evaluate path through safety gates
FileVerdict PurgeEngine::evaluate(const string& path, const AppManifest& manifest) const {
    FileVerdict v;
    v.path = path;
    v.app_name = manifest.app_name;
    v.confidence = manifest.confidence;

    error_code ec;
    bool exists = fs::exists(path, ec);
    if (!exists) {
        v.gate = GateResult::NotFound;
        v.reason = "File no longer exists on disk";
        return v;
    }

    v.is_directory = fs::is_directory(path, ec);
    v.size_bytes = path_size(path);

    auto g1 = gate1_system_path(path);
    if (g1 != GateResult::Safe) {
        v.gate = g1;
        v.reason = "System directory — managed by apt, never touched by SAM";
        return v;
    }

    auto g2 = gate2_safe_zone(path);
    if (g2 != GateResult::Safe) {
        v.gate = g2;
        v.reason = "Personal safe zone — SAM never deletes user data";
        return v;
    }

    auto g3 = gate3_dependency(path, manifest);
    if (g3 != GateResult::Safe) {
        v.gate = g3;
        v.reason = "Shared library — another app may depend on this";
        return v;
    }

    auto g4 = gate4_confidence(v.confidence);
    if (g4 != GateResult::Safe) {
        v.gate = g4;
        v.reason = "Low confidence attribution — requires user review";
        return v;
    }

    auto g5 = gate5_age(path);
    if (g5 != GateResult::Safe) {
        v.gate = g5;
        v.reason = "File is less than " + to_string(config_.protect_newer_than_days) + " days old — protected";
        return v;
    }

    v.gate = GateResult::Safe;
    v.reason = "Passed all safety gates";
    return v;
}

// Calculate directory/file size
int64_t PurgeEngine::path_size(const string& path) const {
    error_code ec;
    if (fs::is_regular_file(path, ec))
        return (int64_t)fs::file_size(path, ec);

    if (fs::is_directory(path, ec)) {
        int64_t total = 0;
        for (auto& e : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
            if (e.is_regular_file(ec))
                total += (int64_t)e.file_size(ec);
        }
        return total;
    }
    return 0;
}

// Create purge plan
PurgePlan PurgeEngine::plan(const AppManifest& manifest) {
    PurgePlan p;
    p.app_name = manifest.app_name;

    for (auto& path : manifest.owned_paths) {
        FileVerdict v = evaluate(path, manifest);

        switch (v.gate) {
            case GateResult::Safe:
                p.auto_delete.push_back(v);
                p.bytes_to_free += v.size_bytes;
                p.files_to_delete += 1;
                break;

            case GateResult::LowConf:
                p.needs_review.push_back(v);
                break;

            default:
                p.skipped.push_back(v);
                p.bytes_skipped += v.size_bytes;
                p.files_skipped += 1;
                break;
        }
    }

    return p;
}

// Display purge plan
void PurgeEngine::print_plan(const PurgePlan& pp) const {
    cout << "\n" << BOLD << "SAM — Removal plan for: " << pp.app_name << RESET << "\n";
    cout << string(52, '-') << "\n\n";

    if (!pp.auto_delete.empty()) {
        cout << GREEN << BOLD << "✓ Will delete automatically ("
             << pp.auto_delete.size() << " items, " << fmt_bytes(pp.bytes_to_free) << "):"
             << RESET << "\n";
        for (auto& v : pp.auto_delete) {
            cout << "  " << v.path << "  " << CYAN << fmt_bytes(v.size_bytes) << RESET << "\n";
        }
        cout << "\n";
    }

    if (!pp.needs_review.empty()) {
        cout << YELLOW << BOLD << "⚠  Needs your review ("
             << pp.needs_review.size() << " items — confidence is INFERRED):"
             << RESET << "\n";
        for (auto& v : pp.needs_review) {
            cout << "  " << v.path << "  " << CYAN << fmt_bytes(v.size_bytes) << RESET
                 << "  [" << v.reason << "]\n";
        }
        cout << "\n";
    }

    if (!pp.skipped.empty()) {
        cout << RED << BOLD << "✗ Skipping (" << pp.skipped.size() << " items):" << RESET << "\n";
        for (auto& v : pp.skipped) {
            cout << "  " << v.path << "  [" << gate_result_str(v.gate) << ": " << v.reason << "]\n";
        }
        cout << "\n";
    }

    cout << string(52, '-') << "\n";
    cout << GREEN  << "  To free:   " << fmt_bytes(pp.bytes_to_free) << RESET << "\n";
    cout << YELLOW << "  To review: " << pp.needs_review.size() << " files" << RESET << "\n";
    cout << RED    << "  Skipped:   " << fmt_bytes(pp.bytes_skipped) << RESET << "\n";
    cout << string(52, '-') << "\n\n";
}

// User confirmation prompt
bool PurgeEngine::prompt_confirm(const PurgePlan&) const {
    if (config_.skip_confirmation) return true;

    cout << "Proceed with deletion? " << BOLD << "[y/N]: " << RESET;
    string ans;
    getline(cin, ans);
    return (!ans.empty() && (ans[0] == 'y' || ans[0] == 'Y'));
}

bool PurgeEngine::prompt_review_inferred(vector<FileVerdict>& needs_review, vector<FileVerdict>& approved) const {
    if (needs_review.empty()) return true;
    if (config_.skip_confirmation) return true;

    cout << YELLOW << BOLD << "\nReview inferred files (SAM is not 100% certain):\n" << RESET;
    cout << "  [d] delete  [k] keep  [a] delete all  [s] skip all\n\n";

    vector<FileVerdict> remaining;
    bool delete_all = false;

    for (auto& v : needs_review) {
        if (delete_all) {
            approved.push_back(v);
            continue;
        }
        cout << "  " << v.path << "  " << fmt_bytes(v.size_bytes) << "\n  > ";
        string ans;
        getline(cin, ans);

        if (ans == "a") { delete_all = true; approved.push_back(v); }
        else if (ans == "d") approved.push_back(v);
        else if (ans == "s") break;
        else remaining.push_back(v);
    }
    needs_review = remaining;
    return true;
}

// Delete single path
bool PurgeEngine::delete_one(const string& path, int64_t& bytes_freed) {
    if (config_.dry_run) {
        cout << "  [DRY RUN] would delete: " << path << "\n";
        return true;
    }

    error_code ec;

    if (starts_with_any_system_prefix(path)) {
        cerr << RED << "  [BLOCKED] system path reached delete_one — BUG: " << path << RESET << "\n";
        return false;
    }
    if (gate2_safe_zone(path) != GateResult::Safe) {
        cerr << RED << "  [BLOCKED] safe zone reached delete_one — BUG: " << path << RESET << "\n";
        return false;
    }

    int64_t sz = path_size(path);

    if (fs::is_directory(path, ec)) {
        fs::remove_all(path, ec);
    } else {
        fs::remove(path, ec);
    }

    if (ec) {
        cerr << RED << "  [FAILED] " << path << ": " << ec.message() << RESET << "\n";
        return false;
    }

    bytes_freed += sz;
    if (config_.on_delete) config_.on_delete(path, sz);
    return true;
}

// Execute plan
PurgeResult PurgeEngine::execute(const PurgePlan& plan) {
    PurgeResult result;

    auto do_delete = [&](const FileVerdict& v) {
        int64_t freed = 0;
        if (delete_one(v.path, freed)) {
            ++result.files_deleted;
            result.bytes_freed += freed;
            result.deleted_paths.push_back(v.path);
        } else {
            ++result.files_failed;
            result.failed_paths.push_back(v.path);
        }
    };

    for (auto& v : plan.auto_delete) {
        do_delete(v);
    }

    for (auto& v : plan.skipped) {
        ++result.files_skipped;
        result.skipped_paths.push_back(v.path);
    }

    result.success = (result.files_failed == 0);
    return result;
}

// Main remove flow
PurgeResult PurgeEngine::remove(const AppManifest& manifest) {
    PurgePlan p = plan(manifest);

    print_plan(p);

    if (p.auto_delete.empty() && p.needs_review.empty()) {
        cout << "Nothing to delete for " << manifest.app_name << "\n";
        PurgeResult res;
        res.success = true;
        return res;
    }

    vector<FileVerdict> approved_inferred;
    prompt_review_inferred(p.needs_review, approved_inferred);

    for (auto& v : approved_inferred) {
        p.bytes_to_free += v.size_bytes;
        p.files_to_delete += 1;
        p.auto_delete.push_back(v);
    }

    if (!prompt_confirm(p)) {
        cout << "Cancelled. Nothing was deleted.\n";
        PurgeResult res;
        res.success = false;
        res.error_message = "User cancelled";
        return res;
    }

    cout << "\nDeleting...\n";
    PurgeResult result = execute(p);

    cout << "\n" << BOLD << "Done." << RESET << "\n";
    cout << GREEN << "  Deleted : " << result.files_deleted << " files  "
         << fmt_bytes(result.bytes_freed) << " freed" << RESET << "\n";
    if (result.files_skipped > 0)
        cout << YELLOW << "  Skipped : " << result.files_skipped << " files" << RESET << "\n";
    if (result.files_failed > 0)
        cout << RED << "  Failed  : " << result.files_failed << " files" << RESET << "\n";
    cout << "\n";

    return result;
}

PurgePlan PurgeEngine::dry_run(const AppManifest& manifest) {
    bool orig = config_.dry_run;
    config_.dry_run = true;
    PurgePlan p = plan(manifest);
    print_plan(p);
    config_.dry_run = orig;
    return p;
}

PurgeResult PurgeEngine::purge_ghost(const string& app_name, const vector<string>& paths) {
    AppManifest manifest;
    manifest.app_name = app_name;
    manifest.owned_paths = paths;
    manifest.confidence = "imported";
    manifest.shared_libs = {};

    return remove(manifest);
}

PurgeResult PurgeEngine::purge_category(const string& category_path, int older_than_days) {
    PurgeResult result;
    error_code ec;

    if (!fs::exists(category_path, ec)) {
        result.error_message = "Path does not exist: " + category_path;
        return result;
    }

    if (category_path.rfind(home_, 0) != 0) {
        result.error_message = "BLOCKED: path is outside home directory: " + category_path;
        cerr << RED << result.error_message << RESET << "\n";
        return result;
    }

    if (gate2_safe_zone(category_path) != GateResult::Safe) {
        result.error_message = "BLOCKED: path is inside a safe zone: " + category_path;
        return result;
    }

    int64_t freed = 0;

    for (auto& entry : fs::recursive_directory_iterator(category_path, fs::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        if (file_age_days(entry.path().string()) < older_than_days)
            continue;

        if (delete_one(entry.path().string(), freed)) {
            ++result.files_deleted;
            result.bytes_freed += freed;
            freed = 0;
        } else {
            ++result.files_failed;
        }
    }

    result.success = (result.files_failed == 0);
    cout << GREEN << "Category clean complete: " << fmt_bytes(result.bytes_freed) << " freed" << RESET << "\n";
    return result;
}

} // namespace SAM