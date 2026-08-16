#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace SAM {

namespace fs = std::filesystem;

// safety check results
enum class GateResult {
    Safe,        // ok to delete
    SystemPath,  // blocked: system path
    SafeZone,    // blocked: user safe zone
    Dependency,  // blocked: needed by another app
    LowConf,     // needs review
    TooNew,      // blocked: less than 7 days old
    NotFound,    // missing file
};

std::string gate_result_str(GateResult g);

// single file verdict
struct FileVerdict {
    std::string path;
    int64_t     size_bytes    = 0;
    GateResult  gate          = GateResult::Safe;
    std::string reason;
    bool        is_directory  = false;
    std::string confidence;
    std::string app_name;
};

// purge plan
struct PurgePlan {
    std::string              app_name;
    std::vector<FileVerdict> auto_delete;
    std::vector<FileVerdict> needs_review;
    std::vector<FileVerdict> skipped;

    int64_t bytes_to_free   = 0;
    int64_t bytes_skipped   = 0;
    int     files_to_delete = 0;
    int     files_skipped   = 0;
};

// purge result
struct PurgeResult {
    bool    success         = false;
    int     files_deleted   = 0;
    int     files_skipped   = 0;
    int     files_failed    = 0;
    int64_t bytes_freed     = 0;
    std::vector<std::string> deleted_paths;
    std::vector<std::string> failed_paths;
    std::vector<std::string> skipped_paths;
    std::string error_message;
};

// manifest for an app
struct AppManifest {
    std::string              app_name;
    std::vector<std::string> owned_paths;
    std::vector<std::string> shared_libs;
    std::string              confidence;
};

// engine config
struct PurgeConfig {
    static constexpr const char* SYSTEM_PREFIXES[] = {
        "/usr", "/lib", "/lib64", "/bin", "/sbin",
        "/etc", "/var", "/sys", "/proc", "/boot",
        "/run", "/dev", "/snap/bin", nullptr
    };

    std::vector<std::string> safe_zones = {
        "Pictures", "Documents", "Videos",
        "Music", "Downloads", ".ssh", ".gnupg",
        ".pki", ".password-store"
    };

    int protect_newer_than_days = 7;
    bool dry_run = false;
    bool skip_confirmation = false;

    std::function<void(const std::string& path, int64_t bytes)> on_delete;
    std::function<void(const std::string& path, const std::string& reason)> on_warn;
};

// main purge engine class
class PurgeEngine {
public:
    explicit PurgeEngine(PurgeConfig config = {});

    PurgePlan plan(const AppManifest& manifest);
    PurgeResult execute(const PurgePlan& plan);
    PurgeResult remove(const AppManifest& manifest);
    PurgePlan dry_run(const AppManifest& manifest);

    PurgeResult purge_ghost(const std::string& app_name, const std::vector<std::string>& paths);
    PurgeResult purge_category(const std::string& category_path, int older_than_days = 90);

private:
    PurgeConfig config_;
    std::string home_;

    GateResult gate1_system_path(const std::string& path) const;
    GateResult gate2_safe_zone  (const std::string& path) const;
    GateResult gate3_dependency (const std::string& path, const AppManifest& manifest) const;
    GateResult gate4_confidence (const std::string& confidence) const;
    GateResult gate5_age        (const std::string& path) const;

    FileVerdict evaluate(const std::string& path, const AppManifest& manifest) const;
    bool delete_one(const std::string& path, int64_t& bytes_freed);

    void print_plan(const PurgePlan& plan) const;
    bool prompt_confirm(const PurgePlan& plan) const;
    bool prompt_review_inferred(std::vector<FileVerdict>& needs_review, std::vector<FileVerdict>& approved) const;

    bool starts_with_any_system_prefix(const std::string& path) const;
    int64_t file_age_days(const std::string& path) const;
    int64_t path_size(const std::string& path) const;
    std::string home() const { return home_; }
};

} // namespace SAM
