cmake_minimum_required(VERSION 4.0)
project(floe
        VERSION 0.1
        LANGUAGES CXX)
include(cmake/platform.cmake)

set(CMAKE_CXX_STANDARD 20)

set (SOURCE_FILES
        src/floe.cpp
        src/floe.hpp
)

add_library(floe STATIC ${SOURCE_FILES})

find_package(OpenSSL REQUIRED)
target_link_libraries(floe PRIVATE OpenSSL::Crypto)

add_subdirectory(test)