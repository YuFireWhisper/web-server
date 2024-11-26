cmake_minimum_required(VERSION 3.16)
project(web-server)

add_definitions(-DPROJECT_ROOT="${CMAKE_SOURCE_DIR}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(${PROJECT_SOURCE_DIR}/server)

add_library(server
    server/src/log.cpp
    server/src/buffer.cpp
    server/src/time_stamp.cpp
)

enable_testing()
find_package(GTest REQUIRED)

# Note: GLOB is used here for convenience but should generally be avoided
# for production code as it won't catch new files until CMake is run again
file(GLOB_RECURSE TEST_SOURCES "server/tests/unit/*.cpp")
foreach(TEST_FILE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    add_executable(${TEST_NAME} ${TEST_FILE})
    target_link_libraries(${TEST_NAME}
        PRIVATE
        server
        GTest::GTest
        GTest::Main
    )
    gtest_discover_tests(${TEST_NAME})
endforeach()
