cmake_minimum_required (VERSION 2.6)
project (7005-asn4)

set (7005-asn4_VERSION_MAJOR 1)
set (7005-asn4_VERSION_MINOR 0)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "-Wall -Wextra -std=c11 -pedantic")
set(CMAKE_C_FLAGS_DEBUG "-ggdb -O0")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -flto")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (CMAKE_BUILD_TYPE MATCHES Release)
    add_definitions(-DNDEBUG)
endif()

add_definitions(-D_POSIX_C_SOURCE=200809L)
add_definitions(-D_DEFAULT_SOURCE)

include_directories(src)
include_directories(${CMAKE_SOURCE_DIR})
link_directories(${CMAKE_SOURCE_DIR})

file(GLOB LOSSY
    "src/lossy/*.c"
    "src/lossy/*.cpp"
    "src/lossy/*.h"
    )
set(LOSSY ${LOSSY} "src/packet.h")

file(GLOB MAIN
    "src/client/*.c"
    "src/client/*.h"
    )

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)

add_executable(7005-asn4-lossy ${LOSSY})
add_executable(7005-asn4 ${MAIN})

target_link_libraries(7005-asn4-lossy rt Threads::Threads m)
target_link_libraries(7005-asn4 rt Threads::Threads dl ${CMAKE_SOURCE_DIR}/libcrypto.a)
