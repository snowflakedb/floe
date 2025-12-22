cmake_minimum_required(VERSION 4.0)
project(floe
        VERSION 0.0.1
        LANGUAGES CXX)
include(cmake/platform.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTING "Build tests" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)

if(ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
endif()

file(GLOB_RECURSE SOURCE_FILES
        "src/*.cpp"
)

file(GLOB_RECURSE INTERNAL_HEADERS
        "src/internal/*.hpp"
)

file(GLOB_RECURSE PUBLIC_HEADERS
        "include/floe/*.hpp"
)

add_library(floe STATIC ${SOURCE_FILES} ${INTERNAL_HEADERS} ${PUBLIC_HEADERS})

target_include_directories(floe
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(floe
    PRIVATE
        OpenSSL::Crypto
)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if(ENABLE_COVERAGE)
    find_program(LCOV_PATH lcov)
    find_program(GENHTML_PATH genhtml)
    
    if(LCOV_PATH AND GENHTML_PATH)
        add_custom_target(coverage
            COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            COMMAND ${LCOV_PATH} --rc derive_function_end_line=0 --capture --directory ${CMAKE_BINARY_DIR}/CMakeFiles/floe.dir --output-file coverage.info --ignore-errors format
            COMMAND ${LCOV_PATH} --rc derive_function_end_line=0 --extract coverage.info '*/src/*' --output-file coverage_filtered.info --ignore-errors format
            COMMAND ${LCOV_PATH} --rc derive_function_end_line=0 --remove coverage_filtered.info '*/tests/*' --output-file coverage_filtered.info --ignore-errors format
            COMMAND ${GENHTML_PATH} --rc derive_function_end_line=0 --ignore-errors category coverage_filtered.info --output-directory coverage_html
            COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated at: ${CMAKE_BINARY_DIR}/coverage_html/index.html"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            DEPENDS tests
            COMMENT "Generating code coverage report..."
        )
    else()
        message(WARNING "lcov or genhtml not found. Coverage target will not be available.")
    endif()
endif()