cmake_minimum_required(VERSION 4.0)
project(floe
        VERSION 0.1
        LANGUAGES CXX)
include(cmake/platform.cmake)

set(CMAKE_CXX_STANDARD 20)

option(BUILD_TESTING "Build tests" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)

if(ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
endif()

set (SOURCE_FILES
        src/floe.cpp
        src/floe.hpp
)

add_library(floe STATIC ${SOURCE_FILES})

find_package(OpenSSL REQUIRED)
target_link_libraries(floe PRIVATE OpenSSL::Crypto)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

if(ENABLE_COVERAGE)
    find_program(LCOV_PATH lcov)
    find_program(GENHTML_PATH genhtml)
    
    if(LCOV_PATH AND GENHTML_PATH)
        add_custom_target(coverage
            COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            COMMAND ${LCOV_PATH} --capture --directory ${CMAKE_BINARY_DIR}/CMakeFiles/floe.dir --output-file coverage.info
            COMMAND ${LCOV_PATH} --extract coverage.info '*/src/*' --output-file coverage_filtered.info
            COMMAND ${GENHTML_PATH} coverage_filtered.info --output-directory coverage_html
            COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated at: ${CMAKE_BINARY_DIR}/coverage_html/index.html"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            DEPENDS unit_tests
            COMMENT "Generating code coverage report..."
        )
    else()
        message(WARNING "lcov or genhtml not found. Coverage target will not be available.")
    endif()
endif()