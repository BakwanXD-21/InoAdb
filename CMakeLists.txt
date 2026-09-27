cmake_minimum_required(VERSION 3.22)
project(inoadb CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Flag super-ringan untuk memangkas ukuran .so hingga ~200KB
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os -ffunction-sections -fdata-sections -fvisibility=hidden -fno-rtti -fno-exceptions")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,--gc-sections -Wl,--strip-all -s")

add_library(inoadb SHARED main.cpp)

target_link_libraries(inoadb
    log
)
