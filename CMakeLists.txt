cmake_minimum_required(VERSION 4.3)
project(dns C)

set(CMAKE_C_STANDARD 17)

add_executable(dns main.c
        hashmap.c
        hashmap.h
        bucket.c
        bucket.h
        helpers.c
        helpers.h)
