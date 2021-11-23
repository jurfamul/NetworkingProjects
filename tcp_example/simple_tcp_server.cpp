#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "util.h"

/**
 * Entrypoint to the program.
 *
 * @param argc count of arguments on command line
 * @param argv character array of command line arguments
 *
 * @return exit code of the program
 */
int main(int argc, char *argv[]) {
  /* alias for command line argument for ip address */
  char *ip_str;
  /* alias for command line argument for port */
  char *port_str;
  /* tcp_socket will be the socket used for sending/receiving */
  int tcp_socket;

  int new_client_socket;
  /* port will be the integer value of the port */
  unsigned int port;

  /* Dest contains the IP address and port in binary format for bind() */
  struct sockaddr_in client_address;
  socklen_t client_address_len;

  /* buffer to use for receiving data */
  static char recv_buf[DEFAULT_BUF_SIZE];

  /* recv_addr is the client who is talking to us */
  struct sockaddr_in recv_addr;
  /* recv_addr_size stores the size of recv_addr */
  socklen_t recv_addr_size;
  /* buffer to use for sending data */
  static char send_buf[DEFAULT_BUF_SIZE];
  /* variable to hold return values from network functions */
  int ret;

  if (argc < 3) {
    std::cerr << "Provide IP PORT as first two arguments." << std::endl;
    return 1;
  }
  /* assign ip_str to the first command line argument */
  ip_str = argv[1];
  /* assign port_str to the second command line argument */
  port_str = argv[2];

  // 1. Create the socket
  tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // 2. Bind the socket
  struct addrinfo hints;
  struct addrinfo *results;
  struct addrinfo *results_it;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_protocol = 0;
  // Use AI_PASSIVE when we are going to call bind() on the address
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;
  ret = getaddrinfo(ip_str, port_str, &hints, &results);

  if (ret != 0) {
    handle_error("getaddrinfo");
    return -1;
  }

  results_it = results;
  ret = -1;
  while (results_it != NULL) {
    std::cout << "Attempting to BIND to " <<
              get_network_address((struct sockaddr *)results_it->ai_addr, results_it->ai_addrlen) << std::endl;
    ret = bind(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
    if (ret == 0) // Success
    {
      break;
    }
    ret = -1;
    handle_error("bind");
    results_it = results_it->ai_next;
  }
  // Whatever happened, we need to free the address list.
  freeaddrinfo(results);

  if (ret == -1) {
    handle_error("bind failed");
    return -1;
  }

  // 3. listen on socket
  ret = listen(tcp_socket, 10);

  if (ret != 0) {
    handle_error("listen");
    return -1;
  }

  // 4. accept new connection on socket
  client_address_len = sizeof(sockaddr_in);
  new_client_socket = accept(tcp_socket, (struct sockaddr *)&client_address, &client_address_len);

  if (new_client_socket == -1) {
    handle_error("accept");
    return -1;
  }

  std::cout << "Accepted connection from " <<
            get_network_address((struct sockaddr *)&client_address, client_address_len) << std::endl;

  // 5. Receive data
  ret = recv(new_client_socket, recv_buf, 2047, 0);

  if (ret <= 0) {
    handle_error("recv failed for some reason");
    close(new_client_socket);
    close(tcp_socket);
    return 1;
  }

  // Original server code, just print out the raw bytes received.
  std::cout << "Received " << ret << " bytes of data." << std::endl;
  recv_buf[ret] = '\0';
  std::cout << "Data received was `" << recv_buf << "'" << std::endl;

  // 6. Send back data
  ret = send(new_client_socket, recv_buf, ret, 0);

  if (ret <= 0) {
    handle_error("send failed for some reason");
    close(new_client_socket);
    close(tcp_socket);
    return 1;
  }

  std::cout << "sent " << ret << " bytes to client" << std::endl;
  close(new_client_socket);
  close(tcp_socket);
  return 0;
}
