cmake_minimum_required(VERSION 4.0)
project(floe_tests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_COVERAGE "Enable code coverage" OFF)

if(ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

Include(FetchContent)

FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.11.0
)

FetchContent_MakeAvailable(Catch2)

function(add_floe_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE Catch2::Catch2WithMain floe)
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/test/common)
    add_test(NAME ${name} COMMAND ${name} ${CATCH_TAGS})
endfunction()

# Test utilities library (shared across tests)
add_library(test_utils STATIC test_utils.cpp test_utils.hpp)
target_link_libraries(test_utils PUBLIC floe)
target_include_directories(test_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Unit tests
add_floe_test(unit_tests unit_tests.cpp)
target_link_libraries(unit_tests PRIVATE test_utils)

# KAT tests - known answer tests for cross-implementation compatibility
add_floe_test(kat_tests kat_tests.cpp)
target_link_libraries(kat_tests PRIVATE test_utils)
set_tests_properties(kat_tests PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Bounce tests - encryption/decryption roundtrip tests
add_floe_test(bounce_tests bounce_tests.cpp)
target_link_libraries(bounce_tests PRIVATE test_utils)
