cmake_minimum_required(VERSION 3.22)
project(inoadb CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Flag pemangkasan ukuran .so (Ukuran super kecil ~200KB - 500KB)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os -ffunction-sections -fdata-sections -fvisibility=hidden -fno-rtti -fno-exceptions -flto")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os -ffunction-sections -fdata-sections -fvisibility=hidden -flto")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,--gc-sections -Wl,--strip-all -Wl,-s -flto")

# Matikan fitur MbedTLS yang tidak dipakai agar build lebih ringan & cepat
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

# Download MbedTLS secara otomatis
include(FetchContent)
FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
)
FetchContent_MakeAvailable(mbedtls)

# Build Target Shared Library
add_library(inoadb SHARED main.cpp)

# Directori include untuk MbedTLS
target_include_directories(inoadb PRIVATE ${mbedtls_SOURCE_DIR}/include)

target_link_libraries(inoadb
    PRIVATE
    log
    mbedtls
    mbedcrypto
    mbedx509
)
