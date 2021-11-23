all: server_example

server_example: test_server.cpp TCPClient.cpp  TCPClient.h  TCPServer.cpp  TCPServer.h  util.cpp  util.h
	g++ -Werror -Wall -std=c++11 test_server.cpp  TCPClient.cpp TCPServer.cpp  util.cpp -o server_example

