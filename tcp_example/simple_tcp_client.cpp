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
  // alias for command line argument string to send to server
  char *data_str;
  /* tcp_socket will be the socket used for sending/receiving */
  int tcp_socket;

  // Variable for the ipv4 server address
  struct sockaddr_in server_address;
  // Variable for the ipv4 server address length
  socklen_t server_address_len;

  /* buffer to use for receiving data */
  static char recv_buf[DEFAULT_BUF_SIZE];
  /* buffer to use for sending data */
  static char send_buf[DEFAULT_BUF_SIZE];

  /* variable to hold return values from network functions */
  int ret;

  if (argc < 4) {
    std::cerr << "Provide IP PORT to connect to as first two arguments, and data string to send as third argument" << std::endl;
    return 1;
  }
  /* assign ip_str to the first command line argument */
  ip_str = argv[1];
  /* assign port_str to the second command line argument */
  port_str = argv[2];
  data_str = argv[3];

  // 1. Create the socket
  tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // 2. Connect the socket to the server.
  // First need to look up a suitable address for the server
  // (may need to do a DNS lookup first!)

  // hints are things we want the returned address to match
  struct addrinfo hints;
  // results is where our list of addresses will be stored
  struct addrinfo *results;
  // results_it is just a pointer to iterate over the list in results
  struct addrinfo *results_it;
  // set hints to all zeroes, these are the "defaults" for the values
  memset(&hints, 0, sizeof(struct addrinfo));
  // Specify we want only ipv4 addresses
  hints.ai_family = AF_INET;
  // Specify that we want a TCP capable address
  hints.ai_socktype = SOCK_STREAM;
  // There are other members of hints that we don't need right now. man getaddrvinfo for details!

  // getaddrinfo will take our hostname, port number and hints, and return a list of compatible addresses
  // these addresses (in results) will be of the correct type for bind or connect.
  ret = getaddrinfo(ip_str, port_str, &hints, &results);

  if (ret != 0) {
    handle_error("getaddrinfo");
    return -1;
  }

  // results_it is an "interator" element for our results
  // results is a list of addresses that match our specifications
  results_it = results;
  ret = -1;
  while (results_it != NULL) {
    std::cout << "Attempting to CONNECT to " <<
              get_network_address(results_it->ai_addr, results_it->ai_addrlen) << std::endl;

    // Actually connect to the server!
    ret = connect(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
    if (ret == 0) // Success
    {
      break;
    }
    ret = -1;
    handle_error("connect");
    // ai_next points to the next element in the linked list of results.
    // if NULL, it means we have reached the end
    results_it = results_it->ai_next;
  }

  // Whatever happened, we need to free the address list.
  freeaddrinfo(results);

  if (ret == -1) {
    handle_error("connect failed");
    return -1;
  }

  // If we get here, it means that we are successfully connected to a server somewhere! Yay!!!
  // That means we can send just by using the socket, as it's already connected.

  ret = send(tcp_socket, data_str, strlen(data_str), 0);
  std::cout << "sent " << ret << " bytes to server" << std::endl;

  // If we expect a result from the server, this is where we would get it.
  ret = recv(tcp_socket, recv_buf, DEFAULT_BUF_SIZE, 0);

  if (ret <= 0) {
    handle_error("recv");
    close(tcp_socket);
    return 1;
  }

  // Original server code, just print out the raw bytes received.
  std::cout << "Received " << ret << " bytes of data." << std::endl;
  recv_buf[ret] = '\0';
  std::cout << "Data received was `" << recv_buf << "'" << std::endl;

  close(tcp_socket);
  return 0;
}
