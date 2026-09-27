cmake_minimum_required(VERSION 3.22)
project(inoadb CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Include BoringSSL
add_subdirectory(external/boringssl EXCLUDE_FROM_ALL)

# 2. Include Header ADB & JNI
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/boringssl/include
)

# 3. Target Shared Library
add_library(inoadb SHARED 
    main.cpp
    # Tambahkan file implementasi adb protocol internal di sini
    # src/adb_client.cpp
    # src/pairing_connection.cpp
)

# 4. Link BoringSSL & Android Syslibs
target_link_libraries(inoadb
    crypto
    ssl
    log
)
