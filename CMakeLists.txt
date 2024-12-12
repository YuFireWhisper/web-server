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
    server/src/inet_address.cpp
    server/src/socket.cpp
    server/src/acceptor.cpp
    server/src/tcp_connection.cpp
    server/src/event_loop_thread.cpp
    server/src/tcp_server.cpp
    server/src/event_loop_thread_pool.cpp
    server/src/http_request.cpp
    server/src/http_response.cpp
    server/src/http_server.cpp
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
    ${TEST_DIR}/log_test.cpp
    ${TEST_DIR}/poller_test.cpp
    ${TEST_DIR}/inet_address_test.cpp
    ${TEST_DIR}/socket_test.cpp
    ${TEST_DIR}/acceptor_test.cpp
    ${TEST_DIR}/tcp_connection_test.cpp
    ${TEST_DIR}/event_loop_thread_test.cpp
    ${TEST_DIR}/event_loop_thread_pool_test.cpp
    ${TEST_DIR}/tcp_server_test.cpp
    ${TEST_DIR}/timer_queue_test.cpp
    ${TEST_DIR}/buffer_test.cpp
    ${TEST_DIR}/http_request_test.cpp
    ${TEST_DIR}/http_response_test.cpp
    ${TEST_DIR}/http_server_test.cpp
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
