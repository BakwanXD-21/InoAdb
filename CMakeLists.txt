cmake_minimum_required(VERSION 3.22)
project(inoadb CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Flag pemangkasan ukuran .so hingga ~200KB
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os -ffunction-sections -fdata-sections -fvisibility=hidden -fno-rtti -fno-exceptions")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,--gc-sections -Wl,--strip-all -s")

# Download MbedTLS secara otomatis saat build (pengganti OpenSSL yang ringan)
include(FetchContent)
FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mbedtls)

# Build Target Shared Library
add_library(inoadb SHARED main.cpp)

target_link_libraries(inoadb
    log
    mbedtls
    mbedcrypto
    mbedx509
)
