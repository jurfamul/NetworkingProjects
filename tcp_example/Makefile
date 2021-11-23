all: tcpclient tcpserver tcpserver_poll tcpserver_select select_example poll_example

tcpclient: simple_tcp_client.cpp util.cpp
	g++ simple_tcp_client.cpp util.cpp -o tcpclient

tcpserver: simple_tcp_server.cpp util.cpp
	g++ simple_tcp_server.cpp util.cpp -o tcpserver

tcpserver_poll: simple_tcp_server_poll.cpp util.cpp
	g++ simple_tcp_server_poll.cpp util.cpp -o tcpserver_poll

tcpserver_select: simple_tcp_server_select.cpp util.cpp
	g++ simple_tcp_server_select.cpp util.cpp -o tcpserver_select

select_example: select_only_example.cpp
	g++ select_only_example.cpp -o select_example

poll_example: poll_only_example.cpp
	g++ poll_only_example.cpp -o poll_example
