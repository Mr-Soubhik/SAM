#include "scanner.hpp"
#include "ledger.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;

namespace SAM {

// helper to get home dir
static string get_home() {
    const char* th = getenv("SAM_TEST_HOME");
    if (th && *th) return th;
    const char* h = getenv("HOME");
    if (h && *h) return h;
    throw runtime_error("$HOME not set");
}

// run shell command and return stdout
static string shell(const string& cmd) {
    char buf[256];
    string result = "";
    FILE* pipe = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!pipe) return "";
    while (fgets(buf, sizeof(buf), pipe)) {
        result += buf;
    }
    pclose(pipe);
    while (!result.empty() && isspace(result.back())) {
        result.pop_back();
    }
    return result;
}

// check command existence
static bool cmd_exists(const string& cmd) {
    return !shell("command -v " + cmd).empty();
}

// make lowercase
static string lower(string s) {
    for (size_t i = 0; i < s.size(); i++) {
        s[i] = tolower(s[i]);
    }
    return s;
}

// trim whitespace
static string trim(string s) {
    size_t l = s.find_first_not_of(" \t\r\n");
    size_t r = s.find_last_not_of(" \t\r\n");
    if (l == string::npos) return "";
    return s.substr(l, r - l + 1);
}

// file timestamps
static int64_t file_atime(const fs::path& p) {
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0) return 0;
    return (int64_t)st.st_atime;
}

static int64_t file_mtime(const fs::path& p) {
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0) return 0;
    return (int64_t)st.st_mtime;
}

static int64_t now_seconds() {
    return chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count();
}

// --- AptReader ---

bool AptReader::available() const {
    return fs::exists(DPKG_STATUS);
}

vector<AppRecord> AptReader::read() {
    vector<AppRecord> result;
    ifstream file(DPKG_STATUS);
    if (!file.is_open()) return result;

    unordered_set<string> gui_apps;
    if (apps_only_) {
        string out = shell("grep -l \"/usr/share/applications/.*\\.desktop$\" /var/lib/dpkg/info/*.list 2>/dev/null | sed 's|.*/||;s|\\.list$||;s|:.*||'");
        istringstream ss(out);
        string pkg;
        while (getline(ss, pkg)) {
            string t = trim(pkg);
            if (!t.empty()) gui_apps.insert(t);
        }
    }

    string line;
    string pkg_name, pkg_version, pkg_status, pkg_section, pkg_priority;

    while (getline(file, line)) {
        if (line.empty()) {
            if (!pkg_name.empty()) {
                bool installed = (pkg_status.find("installed") != string::npos);
                bool keep = true;

                if (apps_only_) {
                    if (!installed) keep = false;
                    else if (gui_apps.find(pkg_name) == gui_apps.end()) keep = false;
                    else if (pkg_name.rfind("lib", 0) == 0 || pkg_name.rfind("python3-", 0) == 0) keep = false;
                }

                if (keep) {
                    AppRecord rec;
                    rec.name = pkg_name;
                    rec.version = pkg_version;
                    rec.source = "apt";
                    rec.is_installed = installed;
                    result.push_back(rec);
                }

                pkg_name.clear();
                pkg_version.clear();
                pkg_status.clear();
                pkg_section.clear();
                pkg_priority.clear();
            }
            continue;
        }

        if (line.rfind("Package:", 0) == 0)
            pkg_name = trim(line.substr(8));
        else if (line.rfind("Version:", 0) == 0)
            pkg_version = trim(line.substr(8));
        else if (line.rfind("Status:", 0) == 0)
            pkg_status = trim(line.substr(7));
        else if (line.rfind("Section:", 0) == 0)
            pkg_section = trim(line.substr(8));
        else if (line.rfind("Priority:", 0) == 0)
            pkg_priority = trim(line.substr(9));
    }

    if (!pkg_name.empty()) {
        bool installed = (pkg_status.find("installed") != string::npos);
        bool keep = true;

        if (apps_only_) {
            if (!installed) keep = false;
            else if (gui_apps.find(pkg_name) == gui_apps.end()) keep = false;
            else if (pkg_name.rfind("lib", 0) == 0 || pkg_name.rfind("python3-", 0) == 0) keep = false;
        }

        if (keep) {
            AppRecord rec;
            rec.name = pkg_name;
            rec.version = pkg_version;
            rec.source = "apt";
            rec.is_installed = installed;
            result.push_back(rec);
        }
    }

    return result;
}

// --- SnapReader ---

bool SnapReader::available() const {
    return cmd_exists("snap");
}

vector<AppRecord> SnapReader::read() {
    vector<AppRecord> result;
    string out = shell("snap list --unicode=never");
    if (out.empty()) return result;

    istringstream ss(out);
    string line;
    bool first = true;
    while (getline(ss, line)) {
        if (first) { first = false; continue; }
        if (line.empty()) continue;

        istringstream ls(line);
        string name, version, rev, tracking, publisher, notes;
        ls >> name >> version >> rev >> tracking >> publisher;
        getline(ls, notes);
        notes = trim(notes);

        if (name.empty()) continue;

        if (notes.find("base") != string::npos || 
            notes.find("core") != string::npos ||
            name.rfind("gnome-", 0) == 0 ||
            name.rfind("gtk-", 0) == 0 ||
            name.rfind("mesa-", 0) == 0 ||
            name.rfind("core", 0) == 0 ||
            name == "bare" || name == "snapd" ||
            name.rfind("kf6-", 0) == 0 ||
            name.rfind("ffmpeg-", 0) == 0 ||
            name.rfind("firmware-", 0) == 0 ||
            name.rfind("snapd-", 0) == 0) {
            continue;
        }

        AppRecord rec;
        rec.name = name;
        rec.version = version;
        rec.source = "snap";
        rec.is_installed = true;
        result.push_back(rec);
    }
    return result;
}

// --- FlatpakReader ---

bool FlatpakReader::available() const {
    return cmd_exists("flatpak");
}

vector<AppRecord> FlatpakReader::read() {
    vector<AppRecord> result;
    string out = shell("flatpak list --columns=application,version");
    if (out.empty()) return result;

    istringstream ss(out);
    string line;
    while (getline(ss, line)) {
        if (line.empty()) continue;
        istringstream ls(line);
        string app_id, version;
        ls >> app_id >> version;
        if (app_id.empty()) continue;

        string friendly = app_id;
        size_t dot = app_id.rfind('.');
        if (dot != string::npos)
            friendly = lower(app_id.substr(dot + 1));

        AppRecord rec;
        rec.name = friendly;
        rec.version = version;
        rec.source = "flatpak";
        rec.is_installed = true;
        rec.aliases = { app_id };
        result.push_back(rec);
    }
    return result;
}

// --- PipReader ---

bool PipReader::available() const {
    return !find_site_packages().empty();
}

vector<fs::path> PipReader::find_site_packages() const {
    vector<fs::path> found;
    string home = get_home();
    fs::path local_lib = fs::path(home) / ".local" / "lib";
    if (!fs::exists(local_lib)) return found;

    error_code ec;
    for (auto& entry : fs::directory_iterator(local_lib, ec)) {
        if (!entry.is_directory(ec)) continue;
        string dname = entry.path().filename().string();
        if (dname.rfind("python", 0) == 0) {
            fs::path sp = entry.path() / "site-packages";
            if (fs::exists(sp))
                found.push_back(sp);
        }
    }
    return found;
}

vector<AppRecord> PipReader::read() {
    vector<AppRecord> result;
    for (auto& sp : find_site_packages()) {
        error_code ec;
        for (auto& entry : fs::directory_iterator(sp, ec)) {
            string dname = entry.path().filename().string();
            if (dname.size() < 10) continue;
            if (dname.substr(dname.size() - 10) != ".dist-info") continue;

            string stem = dname.substr(0, dname.size() - 10);
            size_t dash = stem.rfind('-');
            if (dash == string::npos) continue;

            string pkg = stem.substr(0, dash);
            string ver = stem.substr(dash + 1);

            for (size_t i = 0; i < pkg.size(); i++) {
                if (pkg[i] == '_') pkg[i] = '-';
            }

            AppRecord rec;
            rec.name = lower(pkg);
            rec.version = ver;
            rec.source = "pip";
            rec.is_installed = true;
            result.push_back(rec);
        }
    }
    return result;
}

// --- NpmReader ---

bool NpmReader::available() const {
    string home = get_home();
    return fs::exists(fs::path(home) / ".local" / "lib" / "node_modules")
        || fs::exists(fs::path(home) / ".npm");
}

vector<AppRecord> NpmReader::read() {
    vector<AppRecord> result;
    string home = get_home();
    fs::path nm = fs::path(home) / ".local" / "lib" / "node_modules";
    if (!fs::exists(nm)) return result;

    error_code ec;
    for (auto& entry : fs::directory_iterator(nm, ec)) {
        if (!entry.is_directory(ec)) continue;
        string pkg = entry.path().filename().string();
        if (pkg.empty() || pkg[0] == '.') continue;

        string version = "unknown";
        fs::path pj = entry.path() / "package.json";
        if (fs::exists(pj)) {
            ifstream f(pj);
            string line;
            while (getline(f, line)) {
                if (line.find("\"version\"") != string::npos) {
                    size_t q1 = line.find(':', 0);
                    if (q1 != string::npos) {
                        size_t a = line.find('"', q1);
                        size_t b = line.find('"', a + 1);
                        if (a != string::npos && b != string::npos)
                            version = line.substr(a + 1, b - a - 1);
                    }
                    break;
                }
            }
        }

        AppRecord rec;
        rec.name = pkg;
        rec.version = version;
        rec.source = "npm";
        rec.is_installed = true;
        result.push_back(rec);
    }
    return result;
}

// --- CargoReader ---

bool CargoReader::available() const {
    string home = get_home();
    return fs::exists(fs::path(home) / ".cargo" / ".crates.toml");
}

vector<AppRecord> CargoReader::read() {
    vector<AppRecord> result;
    string home = get_home();
    fs::path crates = fs::path(home) / ".cargo" / ".crates.toml";
    ifstream f(crates);
    if (!f.is_open()) return result;

    regex pat(R"("([a-zA-Z0-9_\-]+)\s+([\d\.]+)\s+\()");
    string line;
    while (getline(f, line)) {
        smatch m;
        if (regex_search(line, m, pat) && m.size() >= 3) {
            AppRecord rec;
            rec.name = m[1].str();
            rec.version = m[2].str();
            rec.source = "cargo";
            rec.is_installed = true;
            result.push_back(rec);
        }
    }
    return result;
}

// --- MavenReader ---

bool MavenReader::available() const {
    string home = get_home();
    return fs::exists(fs::path(home) / ".m2" / "repository");
}

vector<AppRecord> MavenReader::read() {
    vector<AppRecord> result;
    string home = get_home();
    fs::path repo = fs::path(home) / ".m2" / "repository";

    error_code ec;
    for (auto& g : fs::directory_iterator(repo, ec)) {
        if (!g.is_directory(ec)) continue;
        for (auto& a : fs::directory_iterator(g.path(), ec)) {
            if (!a.is_directory(ec)) continue;
            string artifact = a.path().filename().string();
            AppRecord rec;
            rec.name = artifact;
            rec.version = "";
            rec.source = "maven";
            rec.is_installed = true;
            result.push_back(rec);
        }
    }
    return result;
}

// --- GradleReader ---

bool GradleReader::available() const {
    string home = get_home();
    return fs::exists(fs::path(home) / ".gradle" / "caches");
}

vector<AppRecord> GradleReader::read() {
    vector<AppRecord> result;
    string home = get_home();
    fs::path caches = fs::path(home) / ".gradle" / "caches";

    error_code ec;
    for (auto& entry : fs::directory_iterator(caches, ec)) {
        if (!entry.is_directory(ec)) continue;
        AppRecord rec;
        rec.name = entry.path().filename().string();
        rec.version = "";
        rec.source = "gradle";
        rec.is_installed = true;
        result.push_back(rec);
    }
    return result;
}

// --- AttributionEngine ---

const vector<string> AttributionEngine::XDG_ROOTS = {
    ".config", ".cache", ".local/share", ".local/lib",
    ".local/bin", "snap", ".var/app"
};

AttributionEngine::AttributionEngine(const vector<AppRecord>& apps) {
    for (auto& app : apps) {
        known_names_.insert(lower(app.name));
        name_index_[lower(app.name)] = &app;
        for (auto& alias : app.aliases)
            known_names_.insert(lower(alias));
    }
}

string AttributionEngine::normalise(const string& s) const {
    string n = lower(s);
    size_t i = n.size();
    while (i > 0 && (isdigit(n[i-1]) || n[i-1] == '.')) --i;
    if (i < n.size() && i > 0 && (n[i-1] == '-' || n[i-1] == '_'))
        n = n.substr(0, i - 1);
    return n;
}

bool AttributionEngine::is_xdg_root(const fs::path& path) const {
    string home = get_home();
    string p = path.string();
    for (auto& root : XDG_ROOTS) {
        string full = home + "/" + root + "/";
        if (p.rfind(full, 0) == 0) return true;
    }
    return false;
}

string AttributionEngine::extract_app_name_from_path(const fs::path& path) const {
    string home = get_home();
    string p = path.string();

    for (auto& root : XDG_ROOTS) {
        string prefix = home + "/" + root + "/";
        if (p.rfind(prefix, 0) == 0) {
            string rest = p.substr(prefix.size());
            size_t slash = rest.find('/');
            string first = (slash == string::npos) ? rest : rest.substr(0, slash);
            return lower(first);
        }
    }
    return "";
}

AttributionEngine::Result AttributionEngine::attribute(const fs::path& path) const {
    string candidate = extract_app_name_from_path(path);

    if (!candidate.empty()) {
        if (known_names_.count(candidate)) {
            string src = name_index_.count(candidate) ? name_index_.at(candidate)->source : "";
            return { candidate, "confirmed", src };
        }

        string norm = normalise(candidate);
        if (known_names_.count(norm)) {
            string src = name_index_.count(norm) ? name_index_.at(norm)->source : "";
            return { norm, "confirmed", src };
        }

        for (auto& kn : known_names_) {
            if (candidate.find(kn) != string::npos && kn.size() > 3)
                return { kn, "imported", "" };
            if (kn.find(candidate) != string::npos && candidate.size() > 3)
                return { kn, "imported", "" };
        }

        return { candidate, "inferred", "" };
    }

    for (auto& part : path) {
        string s = lower(part.string());
        if (known_names_.count(s))
            return { s, "imported", "" };
        string ns = normalise(s);
        if (known_names_.count(ns))
            return { ns, "imported", "" };
    }

    return { "", "inferred", "" };
}

// --- CategoryScanner ---

const vector<CategoryScanner::CategoryDef> CategoryScanner::KNOWN_CATEGORIES = {
    { "Node.js cache",       ".npm",                    "npm package cache"         },
    { "Node version mgr",    ".nvm",                    "nvm node versions"          },
    { "Python pip cache",    ".cache/pip",              "pip download cache"         },
    { "Rust registry",       ".cargo/registry",         "cargo crate registry"       },
    { "Rust toolchains",     ".rustup",                 "rustup toolchain installs"  },
    { "Maven repository",    ".m2/repository",          "maven artifact cache"       },
    { "Gradle caches",       ".gradle/caches",          "gradle build cache"         },
    { "Yarn cache",          ".cache/yarn",             "yarn package cache"         },
    { "Go modules",          "go/pkg/mod",              "go module cache"            },
    { "Ollama AI models",    ".ollama/models",          "ollama model weights"       },
    { "HuggingFace cache",   ".cache/huggingface",      "huggingface model cache"    },
    { "Torch model cache",   ".cache/torch",            "pytorch model weights"      },
    { "Whisper models",      ".cache/whisper",          "whisper transcription models"},
    { "LM Studio models",    ".cache/lm-studio",        "lm studio models"           },
    { "Snap user data",      "snap",                    "snap application data"      },
    { "Flatpak user data",   ".var/app",                "flatpak application data"   },
    { "Thumbnail cache",     ".cache/thumbnails",       "desktop thumbnail cache"    },
    { "Font cache",          ".cache/fontconfig",       "font configuration cache"   },
    { "Browser cache",       ".cache/mozilla",          "firefox browser cache"      },
    { "Chrome cache",        ".cache/google-chrome",    "chrome browser cache"       },
};

CategoryScanner::CategoryScanner(const string& home, int stale_days)
    : home_(home), stale_days_(stale_days) {}

int64_t CategoryScanner::dir_size(const fs::path& p, int64_t& last_accessed) {
    int64_t total = 0;
    last_accessed = 0;
    error_code ec;

    for (auto& entry : fs::recursive_directory_iterator(p, fs::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        auto sz = entry.file_size(ec);
        if (!ec) total += (int64_t)sz;

        int64_t at = file_atime(entry.path());
        if (at > last_accessed) last_accessed = at;
    }
    return total;
}

CategoryReport CategoryScanner::scan_one(const CategoryDef& def) {
    fs::path full = fs::path(home_) / def.rel_path;
    CategoryReport r;
    r.category = def.category;
    r.path = full.string();
    r.total_bytes = 0;
    r.last_accessed = 0;
    r.file_count = 0;
    r.safe_to_clean = false;

    if (!fs::exists(full)) return r;

    int64_t la = 0;
    r.total_bytes = dir_size(full, la);
    r.last_accessed = la;

    error_code ec;
    for (auto& e : fs::recursive_directory_iterator(full, fs::directory_options::skip_permission_denied, ec)) {
        if (e.is_regular_file(ec)) ++r.file_count;
    }

    int64_t stale_threshold = now_seconds() - (int64_t)stale_days_ * 86400;
    r.safe_to_clean = (la > 0 && la < stale_threshold);

    return r;
}

vector<CategoryReport> CategoryScanner::scan() {
    vector<CategoryReport> result;
    for (auto& def : KNOWN_CATEGORIES) {
        auto r = scan_one(def);
        if (r.total_bytes > 0)
            result.push_back(r);
    }
    return result;
}

// --- GhostDetector ---

const vector<string> GhostDetector::XDG_DIRS = {
    ".config", ".cache", ".local/share", ".local/lib",
    "snap", ".var/app"
};

GhostDetector::GhostDetector(
    const string& home,
    const vector<AppRecord>& installed,
    const vector<AppRecord>& all_known)
    : home_(home)
{
    for (auto& a : installed) {
        if (a.is_installed) installed_names_.insert(lower(a.name));
    }
    for (auto& a : all_known) {
        all_known_names_.insert(lower(a.name));
    }
}

bool GhostDetector::has_home_presence(const string& app_name) {
    for (auto& xdg : XDG_DIRS) {
        fs::path p = fs::path(home_) / xdg / app_name;
        if (fs::exists(p)) return true;
    }
    return false;
}

int64_t GhostDetector::calc_size(const vector<string>& paths) {
    int64_t total = 0;
    for (auto& p : paths) {
        error_code ec;
        if (fs::is_directory(p, ec)) {
            for (auto& e : fs::recursive_directory_iterator(p, fs::directory_options::skip_permission_denied, ec)) {
                if (e.is_regular_file(ec))
                    total += (int64_t)e.file_size(ec);
            }
        } else if (fs::is_regular_file(p, ec)) {
            total += (int64_t)fs::file_size(p, ec);
        }
    }
    return total;
}

vector<GhostApp> GhostDetector::detect() {
    vector<GhostApp> ghosts;

    for (auto& name : all_known_names_) {
        if (installed_names_.count(name)) continue;

        vector<string> remaining;
        for (auto& xdg : XDG_DIRS) {
            fs::path p = fs::path(home_) / xdg / name;
            if (fs::exists(p))
                remaining.push_back(p.string());
        }

        if (remaining.empty()) continue;

        int64_t sz = calc_size(remaining);
        GhostApp g;
        g.name = name;
        g.last_known_source = "apt";
        g.remaining_paths = remaining;
        g.total_bytes = sz;
        ghosts.push_back(g);
    }

    return ghosts;
}

// --- HomeScanner ---

HomeScanner::HomeScanner(ScanConfig config)
    : config_(move(config))
    , home_(get_home())
    , ledger_(nullptr)
{}

HomeScanner::HomeScanner(Ledger& ledger, ScanConfig config)
    : config_(move(config))
    , home_(get_home())
    , ledger_(&ledger)
{}

vector<unique_ptr<IReader>> HomeScanner::make_readers() {
    vector<unique_ptr<IReader>> readers;
    readers.push_back(make_unique<AptReader>(config_.user_only));
    readers.push_back(make_unique<SnapReader>());
    readers.push_back(make_unique<FlatpakReader>());
    readers.push_back(make_unique<PipReader>());
    readers.push_back(make_unique<NpmReader>());
    readers.push_back(make_unique<CargoReader>());
    readers.push_back(make_unique<MavenReader>());
    readers.push_back(make_unique<GradleReader>());
    return readers;
}

vector<AppRecord> HomeScanner::run_readers(const vector<unique_ptr<IReader>>& readers) {
    vector<AppRecord> all;
    for (auto& r : readers) {
        if (!r->available()) continue;
        auto apps = r->read();
        cout << "  [" << r->name() << "] found " << apps.size() << " packages\n";
        for (auto& a : apps) all.push_back(a);
    }
    return all;
}

bool HomeScanner::should_skip(const fs::path& path) const {
    string name = path.filename().string();
    for (auto& s : config_.skip_dirs) {
        if (name == s) return true;
    }
    return false;
}

bool HomeScanner::is_safe_zone(const fs::path& path) const {
    for (auto& sz : config_.safe_zones) {
        fs::path safe = fs::path(home_) / sz;
        auto [a, b] = mismatch(safe.begin(), safe.end(), path.begin());
        if (a == safe.end()) return true;
    }
    return false;
}

string HomeScanner::classify_file_type(const fs::path& path, const string& rel_path) const {
    auto starts_with = [](const string& s, const string& sub) {
        return s.size() >= sub.size() && s.compare(0, sub.size(), sub) == 0;
    };

    if (starts_with(rel_path, ".cache/"))  return "cache";
    if (starts_with(rel_path, ".config/")) return "config";
    if (starts_with(rel_path, ".local/share/")) return "data";
    if (starts_with(rel_path, ".local/bin/"))   return "binary";
    if (starts_with(rel_path, ".local/lib/"))   return "library";
    if (starts_with(rel_path, "snap/"))     return "data";
    if (starts_with(rel_path, ".var/app/"))  return "data";

    string ext = lower(path.extension().string());
    if (ext == ".log")  return "log";
    if (ext == ".conf" || ext == ".ini" || ext == ".toml" || ext == ".yaml" || ext == ".json" || ext == ".cfg") return "config";
    if (ext == ".so" || ext == ".a")  return "library";
    if (ext == ".gguf" || ext == ".safetensors" || ext == ".bin"  || ext == ".pt" || ext == ".ckpt") return "model";

    return "unknown";
}

void HomeScanner::walk_home(const vector<AppRecord>& known_apps, ScanResult& result, Ledger* ledger) {
    AttributionEngine engine(known_apps);

    const vector<string> WALK_ROOTS = {
        ".config", ".cache", ".local/share",
        ".local/bin", ".local/lib",
        "snap", ".var/app"
    };

    for (auto& root_name : WALK_ROOTS) {
        fs::path root = fs::path(home_) / root_name;
        if (!fs::exists(root)) continue;

        error_code ec;
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;

        for (; it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }

            const auto& entry = *it;
            const fs::path& p = entry.path();

            if (it.depth() == 0 && entry.is_directory(ec)) {
                if (should_skip(p)) {
                    it.disable_recursion_pending();
                    continue;
                }
                if (is_safe_zone(p)) {
                    it.disable_recursion_pending();
                    continue;
                }

                auto attr = engine.attribute(p);
                int64_t la = 0;
                int64_t sz = CategoryScanner::dir_size(p, la);
                string rel = p.string().substr(home_.size() + 1);

                HomeFile hf;
                hf.path = p.string();
                hf.attributed_to = attr.app_name;
                hf.source = attr.source;
                hf.confidence = attr.confidence;
                hf.is_directory = true;
                hf.is_symlink = entry.is_symlink(ec);
                hf.size_bytes = sz;
                hf.last_accessed = la;
                hf.last_modified = file_mtime(p);
                hf.file_type = classify_file_type(p, rel);

                if (ledger && !attr.app_name.empty()) {
                    int app_id = ledger->get_app_id(attr.app_name);
                    if (app_id != -1) {
                        ledger->record_file(app_id, p.string(), sz, attr.confidence, hf.file_type);
                    }
                }

                result.home_files.push_back(move(hf));
                result.total_home_bytes += sz;
                it.disable_recursion_pending();
            }
        }
    }
}

ScanResult HomeScanner::scan() {
    auto t0 = chrono::steady_clock::now();
    ScanResult result;

    cout << "\nSAM Home Scanner starting...\n";
    cout << "Home: " << home_ << "\n\n";

    cout << "Step 1 — Reading package databases:\n";
    auto readers = make_readers();
    auto known_apps = run_readers(readers);
    result.known_apps = known_apps;
    cout << "  Total known packages: " << known_apps.size() << "\n\n";

    if (ledger_) {
        ledger_->begin_transaction();
        try {
            for (auto& r : readers) {
                ledger_->remove_apps_by_source(r->name());
            }
            for (auto& a : known_apps) {
                LedgerAppRecord rec;
                rec.name = a.name;
                rec.version = a.version;
                rec.install_method = a.source;
                rec.status = a.is_installed ? "active" : "ghost";
                ledger_->add_or_update_app(rec);
            }
            ledger_->commit();
        } catch (...) {
            ledger_->rollback();
            throw;
        }
    }

    cout << "Step 2 — Walking home directory (Shallow Scan):\n";
    if (ledger_) ledger_->begin_transaction();
    try {
        walk_home(known_apps, result, ledger_);

        if (ledger_) {
            for (auto& a : known_apps) {
                int id = ledger_->get_app_id(a.name);
                if (id != -1) ledger_->update_app_totals(id);
            }
        }

        if (ledger_) ledger_->commit();
    } catch (...) {
        if (ledger_) ledger_->rollback();
        throw;
    }

    cout << "  App directories found: " << result.home_files.size() << "\n";
    cout << "  Total tracked size:    " << result.total_home_bytes / (1024*1024) << " MB\n\n";

    cout << "Step 3 — Scanning language and tool caches:\n";
    CategoryScanner cat(home_, config_.stale_days);
    result.categories = cat.scan();
    for (auto& c : result.categories) {
        result.total_cache_bytes += c.total_bytes;
    }
    cout << "  Found " << result.categories.size() << " cache categories.\n";
    cout << "  Total cache size: " << result.total_cache_bytes / (1024*1024) << " MB\n\n";

    cout << "Step 4 — Detecting ghost apps:\n";
    vector<AppRecord> installed, all_known;
    for (auto& a : known_apps) {
        all_known.push_back(a);
        if (a.is_installed) installed.push_back(a);
    }

    GhostDetector gd(home_, installed, all_known);
    result.ghosts = gd.detect();

    if (ledger_) {
        ledger_->begin_transaction();
        try {
            for (auto& g : result.ghosts) {
                result.total_ghost_bytes += g.total_bytes;
                LedgerAppRecord rec;
                rec.name = g.name;
                rec.status = "ghost";
                ledger_->add_or_update_app(rec);
            }
            ledger_->commit();
        } catch (...) {
            ledger_->rollback();
            throw;
        }
    } else {
        for (auto& g : result.ghosts) result.total_ghost_bytes += g.total_bytes;
    }

    auto t1 = chrono::steady_clock::now();
    result.scan_duration_ms = (int)chrono::duration_cast<chrono::milliseconds>(t1 - t0).count();

    cout << "\n── Active applications ─────────────────\n";
    cout << "  " << result.known_apps.size() << " tracked packages processed.\n";
    cout << "  " << result.total_home_bytes / (1024*1024) << " MB active storage used.\n\n";

    if (!result.ghosts.empty()) {
        cout << "── Ghost apps (remove to recover space) ────\n";
        for (auto& g : result.ghosts) {
            cout << "  GHOST  " << left << setw(20) << g.name
                 << "  " << g.total_bytes / (1024*1024) << " MB\n";
        }
    } else {
        cout << "  No ghost apps found.\n";
    }

    cout << "\n─────────────────────────────────────────\n";
    cout << "Scan complete in " << result.scan_duration_ms << " ms\n";
    cout << "─────────────────────────────────────────\n\n";

    return result;
}

vector<GhostApp> HomeScanner::scan_ghosts_only() {
    auto readers = make_readers();
    auto known_apps = run_readers(readers);
    vector<AppRecord> installed, all_known;
    for (auto& a : known_apps) {
        all_known.push_back(a);
        if (a.is_installed) installed.push_back(a);
    }
    GhostDetector gd(home_, installed, all_known);
    return gd.detect();
}

vector<CategoryReport> HomeScanner::scan_categories_only() {
    CategoryScanner cat(home_, config_.stale_days);
    return cat.scan();
}

} // namespace SAM
