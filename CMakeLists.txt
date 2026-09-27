cmake_minimum_required(VERSION 3.22)
project(inoadb CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Library JNI utama ----
add_library(inoadb SHARED main.cpp)

target_link_libraries(inoadb
    log
)
