#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace SAM {

namespace fs = std::filesystem;

// package info from readers
struct AppRecord {
    std::string name;
    std::string version;
    std::string source;
    bool        is_installed;
    std::vector<std::string> aliases;
};

// file found during scan
struct HomeFile {
    std::string path;
    std::string attributed_to;
    std::string source;
    std::string confidence;
    bool        is_directory;
    bool        is_symlink;
    int64_t     size_bytes;
    int64_t     last_accessed;
    int64_t     last_modified;
    std::string file_type;
};

// language cache info
struct CategoryReport {
    std::string category;
    std::string path;
    int64_t     total_bytes;
    int64_t     last_accessed;
    bool        safe_to_clean;
    int         file_count;
};

// uninstalled app with leftover files
struct GhostApp {
    std::string name;
    std::string last_known_source;
    std::vector<std::string> remaining_paths;
    int64_t     total_bytes;
};

// scan results container
struct ScanResult {
    std::vector<AppRecord>       known_apps;
    std::vector<HomeFile>        home_files;
    std::vector<CategoryReport>  categories;
    std::vector<GhostApp>        ghosts;
    int64_t                      total_home_bytes   = 0;
    int64_t                      total_ghost_bytes  = 0;
    int64_t                      total_cache_bytes  = 0;
    int                          scan_duration_ms   = 0;
};

// scanner options
struct ScanConfig {
    std::vector<std::string> safe_zones = {
        "Pictures", "Documents", "Videos",
        "Music", "Downloads"
    };

    std::vector<std::string> skip_dirs = {
        ".git", "__pycache__", ".venv", "venv",
        "env", ".tox", ".pytest_cache"
    };

    int max_depth = 8;
    int stale_days = 90;
    int64_t unknown_flag_bytes = 100 * 1024 * 1024;
    bool user_only = true;

    std::function<void(const std::string&, int)> on_progress;
};

// base reader class
class IReader {
public:
    virtual ~IReader() = default;
    virtual std::string name() const = 0;
    virtual bool        available() const = 0;
    virtual std::vector<AppRecord> read() = 0;
};

// package readers
class AptReader : public IReader {
public:
    explicit AptReader(bool apps_only = false) : apps_only_(apps_only) {}
    std::string name() const override { return "apt"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
private:
    bool apps_only_;
    static constexpr const char* DPKG_STATUS = "/var/lib/dpkg/status";
};

class SnapReader : public IReader {
public:
    std::string name() const override { return "snap"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
};

class FlatpakReader : public IReader {
public:
    std::string name() const override { return "flatpak"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
};

class PipReader : public IReader {
public:
    std::string name() const override { return "pip"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
private:
    std::vector<fs::path> find_site_packages() const;
};

class NpmReader : public IReader {
public:
    std::string name() const override { return "npm"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
};

class CargoReader : public IReader {
public:
    std::string name() const override { return "cargo"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
};

class MavenReader : public IReader {
public:
    std::string name() const override { return "maven"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
};

class GradleReader : public IReader {
public:
    std::string name() const override { return "gradle"; }
    bool available() const override;
    std::vector<AppRecord> read() override;
};

// matches paths to app names
class AttributionEngine {
public:
    explicit AttributionEngine(const std::vector<AppRecord>& apps);

    struct Result {
        std::string app_name;
        std::string confidence;
        std::string source;
    };

    Result attribute(const fs::path& path) const;

private:
    std::unordered_map<std::string, const AppRecord*> name_index_;
    std::unordered_set<std::string> known_names_;
    static const std::vector<std::string> XDG_ROOTS;

    bool is_xdg_root(const fs::path& path) const;
    std::string extract_app_name_from_path(const fs::path& path) const;
    std::string normalise(const std::string& s) const;
};

// scans dev caches like npm/cargo
class CategoryScanner {
public:
    explicit CategoryScanner(const std::string& home, int stale_days = 90);
    std::vector<CategoryReport> scan();

private:
    std::string home_;
    int stale_days_;

    struct CategoryDef {
        std::string category;
        std::string rel_path;
        std::string description;
    };

    static const std::vector<CategoryDef> KNOWN_CATEGORIES;
    CategoryReport scan_one(const CategoryDef& def);

public:
    static int64_t dir_size(const fs::path& p, int64_t& last_accessed);
};

// finds leftover files from removed apps
class GhostDetector {
public:
    GhostDetector(const std::string& home,
                  const std::vector<AppRecord>& installed,
                  const std::vector<AppRecord>& all_known);

    std::vector<GhostApp> detect();

private:
    std::string home_;
    std::unordered_set<std::string> installed_names_;
    std::unordered_set<std::string> all_known_names_;
    static const std::vector<std::string> XDG_DIRS;

    bool has_home_presence(const std::string& app_name);
    int64_t calc_size(const std::vector<std::string>& paths);
};

class Ledger;

// main scanner class
class HomeScanner {
public:
    explicit HomeScanner(ScanConfig config = {});
    HomeScanner(Ledger& ledger, ScanConfig config = {});

    ScanResult scan();
    std::vector<GhostApp> scan_ghosts_only();
    std::vector<CategoryReport> scan_categories_only();
    std::string home() const { return home_; }

private:
    ScanConfig  config_;
    std::string home_;
    Ledger*     ledger_ = nullptr;

    std::vector<std::unique_ptr<IReader>> make_readers();
    std::vector<AppRecord> run_readers(const std::vector<std::unique_ptr<IReader>>& readers);

    void walk_home(const std::vector<AppRecord>& known_apps,
                   ScanResult& result,
                   Ledger* ledger = nullptr);

    std::string classify_file_type(const fs::path& path, const std::string& rel_path) const;
    bool should_skip(const fs::path& path) const;
    bool is_safe_zone(const fs::path& path) const;
};

} // namespace SAM
