cmake_minimum_required(VERSION 3.20)
project(dns C)

set(CMAKE_C_STANDARD 17)

add_library(dnscore STATIC
        src/helpers.c
        src/packet.c
        src/network.c
        src/cache.c
        src/pending.c
        src/resolver.c
        src/blocklist.c)

target_include_directories(dnscore PUBLIC include)

add_executable(dns src/main.c)
target_link_libraries(dns PRIVATE dnscore)

enable_testing()
foreach(name packet cache helpers pending blocklist resolver network)
    add_executable(test_${name} tests/test_${name}.c)
    target_link_libraries(test_${name} PRIVATE dnscore)
    add_test(NAME ${name} COMMAND test_${name})
endforeach()

# main.c only parses arguments before starting the server, so check that by running it
add_test(NAME cli_help COMMAND dns -h)
foreach(args "-p;0" "-p;65536" "-p;12abc" "-p;" "-b;256.0.0.1" "-x")
    string(REPLACE ";" "_" test_name "cli_rejects${args}")
    add_test(NAME ${test_name} COMMAND dns ${args})
    set_tests_properties(${test_name} PROPERTIES WILL_FAIL TRUE)
endforeach()

# Runs the server and queries it with dig. Exits 77 (skipped) if dig isn't installed
add_test(NAME dig COMMAND sh ${PROJECT_SOURCE_DIR}/tests/test_dig.sh $<TARGET_FILE:dns>)
set_tests_properties(dig PROPERTIES SKIP_RETURN_CODE 77)

target_compile_options(dnscore PUBLIC -Wall -Wextra -g -O2)
target_compile_definitions(dnscore PUBLIC BLOCKLIST_DIR="${PROJECT_SOURCE_DIR}/blocklists")