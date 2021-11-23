//
// Created by nate a long time ago
//

#include "TCPServer.h"
#include <iostream>
#include "util.h"


TCPServer::TCPServer(const char *host_string, const char *port_string) {
  struct addrinfo hints;
  struct addrinfo *results;
  struct addrinfo *result_it;
  int ret;
  ready = false;

  memset(&hints, 0, sizeof(struct addrinfo));
  //hints.ai_family = AF_UNSPEC;
  hints.ai_family = AF_UNSPEC;
  hints.ai_canonname = NULL;
  hints.ai_socktype = SOCK_STREAM;
  //hints.ai_flags = AI_PASSIVE;
  hints.ai_flags = AI_ALL;

  ret = getaddrinfo(host_string, port_string, &hints, &results);

  if (ret != 0) {
    std::cerr << "getaddrinfo error: " << gai_strerror(errno) << std::endl;
  }

  result_it = results;
  while (result_it != NULL) {
#if DEBUG
    std::cout << "Found address " << printable_address((struct sockaddr_storage *)result_it->ai_addr, result_it->ai_addrlen) << std::endl;
#endif
    result_it = result_it->ai_next;
  }

  result_it = results;
  server_socket = -1;
  while (result_it != NULL) {
#if DEBUG
    std::cout << "Trying to create socket on " << printable_address((struct sockaddr_storage *)result_it->ai_addr, result_it->ai_addrlen) << std::endl;
#endif
    server_socket = socket(result_it->ai_family, result_it->ai_socktype, result_it->ai_protocol);
    if (server_socket == -1) {
      perror("socket");
    } else {
      int enable = 1;
      if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0)
            perror("setsockopt(SO_REUSEPORT) failed");
      if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
            perror("setsockopt(SO_REUSEADDR) failed");
      if (bind(server_socket, result_it->ai_addr, result_it->ai_addrlen) == 0) {
        memcpy(&server_addr, result_it->ai_addr, result_it->ai_addrlen);
        server_addr_len = result_it->ai_addrlen;
#if DEBUG
        std::cout << "Success binding to " << get_printable_address() << std::endl;
#endif
        ready = true;

        break;
      }
      else {
        perror("bind");
      }
    }
    result_it = result_it->ai_next;
  }

  freeaddrinfo(results);
}

TCPServer::TCPServer() {
  ready = false;
  memset(&server_addr, 0, sizeof(struct sockaddr_storage));
}

bool TCPServer::start_server() {
  int ret;
  if (ready == false)
    return false;

  ret = listen(server_socket, 500);

  if (ret != 0) {
    perror("listen");
    return false;
  }

  is_listening = true;
  return true;
}

bool TCPServer::stop_server() {
  if ((is_listening == true) && (ready == true)) {
    close(server_socket);
    server_socket = 0;
    is_listening = false;
    ready = false;
    return true;
  } else {
    std::cerr << "Attempted to stop non-running server!" << std::endl;
  }

  return false;
}

int TCPServer::accept_connection(struct sockaddr_storage *client_addr, socklen_t *client_addr_len) {
  int ret;

  ret = accept(server_socket, (struct sockaddr *)client_addr, client_addr_len);
  if (ret == -1) {
    perror("accept");
  }

  return ret;
}

int TCPServer::get_server_socket() {
  return server_socket;
}

const char *TCPServer::get_printable_address() {
  return printable_address(&server_addr, server_addr_len);
}

bool TCPServer::has_ipv4_address() {
  if (server_addr.ss_family == AF_INET)
    return true;
  return false;
}

bool TCPServer::has_ipv6_address() {
  if (server_addr.ss_family == AF_INET6)
    return true;
  return false;
}

struct sockaddr_in *TCPServer::get_ipv4_address() {
  return (sockaddr_in*)&server_addr;
}

struct sockaddr_in6 *TCPServer::get_ipv6_address() {
  return (sockaddr_in6 *)&server_addr;
}

uint16_t TCPServer::get_listen_port() {
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  if (server_addr.ss_family == AF_INET) {
    v4 = (struct sockaddr_in *)&server_addr;
    return ntohs(v4->sin_port);
  } else if (server_addr.ss_family == AF_INET6) {
    v6 = (struct sockaddr_in6 *)&server_addr;
    return ntohs(v6->sin6_port);
  } else {
    std::cerr << "Failed to read port for server listen address." << std::endl;
    return 0;
  }
}
