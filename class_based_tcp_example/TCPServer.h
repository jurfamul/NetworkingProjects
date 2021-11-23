//
// Created by nate a long time ago
//

#ifndef CLASS_BASED_TCP_EXAMPLE_TCPSERVER_H
#define CLASS_BASED_TCP_EXAMPLE_TCPSERVER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <vector>
#include <netdb.h>

#define DEFAULT_LISTEN_PORT "17777"
#define DEFAULT_LISTEN_HOST "0.0.0.0"

class TCPServer {
public:
  TCPServer(const char *host_string, const char *port_string);
  TCPServer();
  bool start_server();
  bool stop_server();
  int accept_connection(struct sockaddr_storage *client_addr, socklen_t *client_addr_len);
  int get_server_socket();
  const char *get_printable_address();
  bool has_ipv4_address();
  bool has_ipv6_address();
  struct sockaddr_in *get_ipv4_address();
  struct sockaddr_in6 *get_ipv6_address();
  uint16_t get_listen_port();
private:
  int server_socket;
  bool is_listening;
  bool ready;
  sockaddr_storage server_addr;
  socklen_t server_addr_len;
};


#endif //CLASS_BASED_TCP_EXAMPLE_TCPSERVER_H
