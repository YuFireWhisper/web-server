cmake_minimum_required(VERSION 3.16)
project(web-server)

add_definitions(-DPROJECT_ROOT="${CMAKE_SOURCE_DIR}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_definitions(-D_GLIBCXX_USE_CXX11_ABI=1)

include_directories(${PROJECT_SOURCE_DIR}/server)

add_library(server
    server/src/thread.cpp
    server/src/poller.cpp
    server/src/epoll_poller.cpp
    server/src/time_stamp.cpp
    server/src/buffer.cpp
    server/src/log.cpp
    server/src/time_stamp.cpp
    server/src/event_loop.cpp
    server/src/channel.cpp
    server/src/timer_queue.cpp
)

enable_testing()
find_package(GTest REQUIRED)
include(GoogleTest)

set(TEST_DIR ${PROJECT_SOURCE_DIR}/server/tests/unit)

set(TEST_FILES
    ${TEST_DIR}/time_stamp_test.cpp
    ${TEST_DIR}/timer_test.cpp
    ${TEST_DIR}/timer_id_test.cpp
    ${TEST_DIR}/event_loop_test.cpp
    ${TEST_DIR}/channel_test.cpp
    ${TEST_DIR}/epoll_poller_test.cpp
)

foreach(TEST_FILE ${TEST_FILES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    add_executable(${TEST_NAME} ${TEST_FILE})
    target_link_libraries(${TEST_NAME}
        PRIVATE
        server
        GTest::GTest
        GTest::Main
        pthread
    )
    gtest_discover_tests(${TEST_NAME})
endforeach()
