cmake_minimum_required(VERSION 3.14)
project(sam)

# Use C++17 for filesystem support
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Find Dependencies
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# 2. Include Directories
include_directories(src ${SQLite3_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# 3. Define the Executable
add_executable(sam 
    src/main.cpp 
    src/ledger.cpp 
    src/scanner.cpp 
    src/purge.cpp
    src/watcher.cpp
)

# 4. Link Libraries
target_link_libraries(sam 
    ${SQLite3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
    stdc++fs
)

# 5. Install Rule
install(TARGETS sam DESTINATION /usr/local/bin)
