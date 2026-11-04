cmake_minimum_required(VERSION 4.3)
project(dns C)

set(CMAKE_C_STANDARD 17)

add_executable(dns
        src/main.c
        src/helpers.c
        src/packet.c
        src/network.c
        src/cache.c
        src/pending.c
        src/resolver.c
        src/blocklist.c)

target_include_directories(dns PRIVATE include)
target_compile_options(dns PRIVATE -Wall -Wextra -g -O2)
target_compile_definitions(dns PRIVATE BLOCKLIST_DIR="${PROJECT_SOURCE_DIR}/blocklists")