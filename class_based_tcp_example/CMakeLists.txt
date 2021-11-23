cmake_minimum_required(VERSION 3.8)
project(class_based_tcp_example)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 11)
find_package(OpenSSL REQUIRED)

set(SOURCE_FILES P2P.h TCPClient.cpp TCPClient.h TCPServer.cpp TCPServer.h util.cpp util.h)
set(TEST_SRV_SOURCES TCPClient.cpp TCPClient.h TCPServer.cpp TCPServer.h util.cpp util.h test_server.cpp)
add_executable(test_simple_server ${TEST_SRV_SOURCES})