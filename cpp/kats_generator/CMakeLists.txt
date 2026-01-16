cmake_minimum_required(VERSION 4.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# KAT Generator Tool
add_executable(create_kats create_kats.cpp)
target_link_libraries(create_kats PRIVATE floe)
target_include_directories(create_kats PRIVATE ${CMAKE_SOURCE_DIR}/include)
