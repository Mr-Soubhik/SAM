#include "watcher.hpp"
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>   
#include <iostream>
#include <string>
#include <fstream>
#include <linux/limits.h>
#include <filesystem>
#include <chrono>

using namespace std;
namespace fs = std::filesystem;

namespace SAM {

// helper to get event name
string getEventName(EventType t) {
    if (t == EventType::Created) return "CREATED";
    if (t == EventType::Modified) return "MODIFIED";
    if (t == EventType::Deleted) return "DELETED";
    if (t == EventType::MovedFrom) return "MOVED_FROM";
    if (t == EventType::MovedTo) return "MOVED_TO";
    if (t == EventType::Attrib) return "ATTRIB";
    return "UNKNOWN";
}

string FileEvent::to_string() const {
    long long ts = timestamp_ns / 1000000; // to ms
    long long displayTs = ts % 1000000000;
    
    string pidStr = "?";
    if (pid > 0) {
        pidStr = std::to_string(pid);
    }

    string pName = process_name;
    if (pName.length() > 14) {
        pName = pName.substr(0, 14);
    }

    string dirStr = "";
    if (is_directory) {
        dirStr = "/";
    }

    // manual string appending instead of format
    return "[" + std::to_string(displayTs) + "ms] " + getEventName(type) + " " + pidStr + " " + pName + " " + path + dirStr;
}

Watcher::Watcher() {
    inotify_fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd_ < 0) {
        cout << "Error: inotify failed\n";
    }

    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        cout << "Error: epoll failed\n";
    }

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = inotify_fd_;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, inotify_fd_, &ev);

    pipe2(stop_pipe_, O_NONBLOCK | O_CLOEXEC);

    epoll_event pev;
    pev.events = EPOLLIN;
    pev.data.fd = stop_pipe_[0];
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, stop_pipe_[0], &pev);
}

Watcher::~Watcher() {
    stop();
    if (inotify_fd_ >= 0) close(inotify_fd_);
    if (epoll_fd_ >= 0) close(epoll_fd_);
    if (stop_pipe_[0] >= 0) close(stop_pipe_[0]);
    if (stop_pipe_[1] >= 0) close(stop_pipe_[1]);
}

void Watcher::add_watch(const fs::path& root) {
    if (!fs::exists(root)) return;
    watch_single(root);

    // loop through all dirs
    error_code ec;
    for (auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec)) {
        if (entry.is_directory(ec)) {
            watch_single(entry.path());
        }
    }
}

void Watcher::start(EventCallback cb, int filter_pid) {
    if (running_ == true) return;
    running_ = true;
    callback_ = cb;
    filter_pid_ = filter_pid;
    worker_ = thread(&Watcher::event_loop, this);
}

void Watcher::stop() {
    if (running_ == false) return;
    running_ = false;
    char b = 1;
    write(stop_pipe_[1], &b, 1);
    if (worker_.joinable()) {
        worker_.join();
    }
}

void Watcher::watch_single(const fs::path& dir) {
    int wd = inotify_add_watch(inotify_fd_, dir.c_str(), WATCH_MASK);
    if (wd < 0) return;

    lock_guard<mutex> lock(map_mutex_);
    wd_to_path_[wd] = dir.string();
}

void Watcher::event_loop() {
    char buf[4096];
    epoll_event events[8];

    while (running_ == true) {
        int n = epoll_wait(epoll_fd_, events, 8, -1);
        if (n < 0) break;

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == stop_pipe_[0]) {
                return;
            }
            if (events[i].data.fd == inotify_fd_) {
                drain_inotify(buf, 4096);
            }
        }
    }
}

void Watcher::drain_inotify(char* buf, size_t buf_size) {
    while (true) {
        int len = read(inotify_fd_, buf, buf_size);
        if (len <= 0) break;

        int offset = 0;
        while (offset < len) {
            inotify_event* event = (inotify_event*)(buf + offset);
            process_inotify_event(event);
            offset += sizeof(inotify_event) + event->len;
        }
    }
}

int Watcher::find_pid_for_file(const string& path) {
    if (filter_pid_ != -1) return filter_pid_;

    for (const auto& entry : fs::directory_iterator("/proc")) {
        string pidStr = entry.path().filename().string();
        
        // check if it's a number manually
        bool isNum = true;
        for (int i = 0; i < pidStr.length(); i++) {
            if (!isdigit(pidStr[i])) {
                isNum = false;
                break;
            }
        }
        if (!isNum) continue;

        int pid = stoi(pidStr);
        fs::path fdDir = entry.path() / "fd";
        
        error_code ec;
        if (!fs::exists(fdDir, ec)) continue;

        for (const auto& fd_entry : fs::directory_iterator(fdDir, ec)) {
            if (ec) break;
            char link_path[PATH_MAX];
            int len = readlink(fd_entry.path().c_str(), link_path, sizeof(link_path)-1);
            if (len != -1) {
                link_path[len] = '\0';
                if (path == link_path) {
                    return pid;
                }
            }
        }
    }
    return -1;
}

string Watcher::get_process_name(int pid) {
    if (pid <= 0) return "unknown";
    ifstream commFile("/proc/" + to_string(pid) + "/comm");
    string name;
    if (getline(commFile, name)) {
        return name;
    }
    return "unknown";
}

void Watcher::process_inotify_event(const inotify_event* ie) {
    string dirPath;
    
    // basic lock and unlock instead of lock_guard here
    map_mutex_.lock();
    if (wd_to_path_.find(ie->wd) == wd_to_path_.end()) {
        map_mutex_.unlock();
        return;
    }
    dirPath = wd_to_path_[ie->wd];
    map_mutex_.unlock();

    string fullPath = dirPath;
    if (ie->len > 0) {
        fullPath += "/";
        fullPath += ie->name;
    }

    EventType type = EventType::Unknown;
    if (ie->mask & IN_CREATE) type = EventType::Created;
    else if (ie->mask & IN_MODIFY) type = EventType::Modified;
    else if (ie->mask & IN_DELETE) type = EventType::Deleted;
    else if (ie->mask & IN_MOVED_FROM) type = EventType::MovedFrom;
    else if (ie->mask & IN_MOVED_TO) type = EventType::MovedTo;
    else if (ie->mask & IN_ATTRIB) type = EventType::Attrib;
    else return;

    if ((ie->mask & IN_CREATE) && (ie->mask & IN_ISDIR)) {
        watch_single(fullPath);
    }

    int pid = find_pid_for_file(fullPath);
    string procName = get_process_name(pid);

    // setup temp event object
    FileEvent ev;
    ev.type = type;
    ev.path = fullPath;
    if (ie->mask & IN_ISDIR) {
        ev.is_directory = true;
    } else {
        ev.is_directory = false;
    }
    ev.cookie = ie->cookie;
    ev.timestamp_ns = chrono::duration_cast<chrono::nanoseconds>(chrono::system_clock::now().time_since_epoch()).count();
    ev.pid = pid;
    ev.process_name = procName;

    event_count_++;
    if (callback_) {
        callback_(ev);
    }
}

size_t Watcher::watched_directories() const {
    lock_guard<mutex> lock(map_mutex_);
    return wd_to_path_.size();
}

size_t Watcher::events_captured() const {
    return event_count_;
}

} // namespace SAM