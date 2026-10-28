cmake_minimum_required(VERSION 4.3)
project(dns C)

set(CMAKE_C_STANDARD 17)

add_executable(dns
        src/main.c
        src/hashmap.c
        src/bucket.c
        src/helpers.c
        src/packet.c
        src/network.c)

target_include_directories(dns PRIVATE include)
target_compile_options(dns PRIVATE -Wall -Wextra)