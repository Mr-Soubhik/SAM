#pragma once

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace SAM {

namespace fs = std::filesystem;

// inotify event types
enum class EventType : uint32_t {
    Created   = IN_CREATE,
    Modified  = IN_MODIFY,
    Deleted   = IN_DELETE,
    MovedFrom = IN_MOVED_FROM,
    MovedTo   = IN_MOVED_TO,
    Attrib    = IN_ATTRIB,
    Unknown   = 0
};

std::string event_type_name(EventType t);

// structure for file event
struct FileEvent {
    EventType   type;
    std::string path;
    bool        is_directory;
    uint32_t    cookie;
    int64_t     timestamp_ns;
    
    int         pid = -1;
    std::string process_name = "unknown";

    std::string to_string() const;
};

// inotify watcher class
class Watcher {
public:
    using EventCallback = std::function<void(const FileEvent&)>;

    static constexpr uint32_t WATCH_MASK =
        IN_CREATE     |
        IN_MODIFY     |
        IN_DELETE     |
        IN_MOVED_FROM |
        IN_MOVED_TO   |
        IN_ATTRIB     |
        IN_DONT_FOLLOW;

    Watcher();
    ~Watcher();

    Watcher(const Watcher&) = delete;
    Watcher& operator=(const Watcher&) = delete;

    void add_watch(const fs::path& root);
    void start(EventCallback cb, int filter_pid = -1);
    void stop();

    size_t watched_directories() const;
    size_t events_captured() const;

private:
    void watch_single(const fs::path& dir);
    void event_loop();
    void drain_inotify(char* buf, size_t buf_size);
    void process_inotify_event(const inotify_event* ie);
    
    int find_pid_for_file(const std::string& path);
    std::string get_process_name(int pid);

    int inotify_fd_   = -1;
    int epoll_fd_     = -1;
    int stop_pipe_[2] = {-1, -1};

    std::thread          worker_;
    std::atomic<bool>    running_{false};
    std::atomic<size_t>  event_count_{0};
    int                  filter_pid_ = -1;
    EventCallback        callback_;

    mutable std::mutex                   map_mutex_;
    std::unordered_map<int, std::string> wd_to_path_;
};

} // namespace SAM