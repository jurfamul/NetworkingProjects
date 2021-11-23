//
// Created by Nathan Evans on 10/20/21.
//

#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/select.h>
#include <vector>
#include <fcntl.h>
#include <poll.h>

#include "util.h"

#define MAX_POLL_FDS 500
#define RECEIVE_BUF_SIZE 2048

struct TCPClient {
  int sock_fd;
  int poll_index;
  char recv_buf[RECEIVE_BUF_SIZE];
  char send_buf[RECEIVE_BUF_SIZE];
  int bytes_to_send;
  int bytes_to_read;
  struct sockaddr client_address;
  socklen_t client_address_len;
};

/**
 *
 * TCP server example. Reads in IP PORT
 * from the command line, and accepts connections via TCP
 * on IP:PORT.
 *
 * e.g., ./tcpserver 127.0.0.1 8888
 *
 * @param argc count of arguments on the command line
 * @param argv array of command line arguments
 * @return 0 on success, non-zero if an error occurred
 */
int main(int argc, char *argv[]) {
  // Alias for argv[1] for convenience
  char *ip_string;
  // Alias for argv[2] for convenience
  char *port_string;

  // Port to send TCP data to. Need to convert from command line string to a number
  unsigned int port;
  // The socket used to send data
  int tcp_socket;
  // Variable used to check return codes from various functions
  int ret;

  int client_socket;

  struct sockaddr_in client_address;
  socklen_t client_address_len;

  struct pollfd pfds[MAX_POLL_FDS];

  int poll_timeout;

  struct addrinfo hints;
  struct addrinfo *results;
  struct addrinfo *results_it;

  int timeout;
  timeout = 2000;

  std::vector<TCPClient *> tcp_clients;

  // Note: this needs to be 3, because the program name counts as an argument!
  if (argc < 3) {
    std::cerr << "Please specify HOSTNAME PORT as first two arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];

  // Create the TCP socket.
  // AF_INET is the address family used for IPv4 addresses
  // SOCK_STREAM indicates creation of a TCP socket
  tcp_socket = socket(AF_INET, SOCK_STREAM, 0);

  // Make sure socket was created successfully, or exit.
  if (tcp_socket == -1) {
    std::cerr << "Failed to create tcp socket!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return 1;
  }

  // Set the socket to be non blocking
  ret = fcntl(tcp_socket, F_SETFL, O_NONBLOCK);
  if (ret == -1) {
    perror("can’t set O_NONBLOCK using fcntl()");
    exit(EXIT_FAILURE);
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_family = AF_INET;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;
  // Instead of using inet_pton, use getaddrinfo to convert.
  ret = getaddrinfo(ip_string, port_string, &hints, &results);

  if (ret != 0) {
    std::cerr << "Getaddrinfo failed with error " << ret << std::endl;
    perror("getaddrinfo");
    return 1;
  }

  // Check we have at least one result
  results_it = results;

  ret = -1;
  while (results_it != NULL) {
    std::cout << "Trying to bind to address " << get_network_address(results_it->ai_addr, results_it->ai_addrlen) << "\n";
    ret = bind(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
    //ret = connect(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
    if (ret == 0) {
      break;
    }
    perror("bind");
    results_it = results_it->ai_next;
  }

  // Whatever happened, we need to free the address list.
  freeaddrinfo(results);

  // Check if connecting succeeded at all
  if (ret != 0) {
    std::cout << "Failed to bind to any addresses!" << std::endl;
    return 1;
  }

  // Listen on the tcp socket
  ret = listen(tcp_socket, 50);

  // Check if connecting succeeded at all
  if (ret != 0) {
    std::cout << "Failed to listen!" << std::endl;
    close(tcp_socket);
    perror("listen");
    return 1;
  }

  while (true) {
    nfds_t socket_count = 0;

    pfds[socket_count].fd = tcp_socket;
    pfds[socket_count].events = POLLIN;
    socket_count += 1;

    // Checking for incoming data on STDIN
    pfds[socket_count].fd = 0;
    pfds[socket_count].events = POLLIN;
    socket_count += 1;

    // Set each file descriptor in our vector to check if it's ready to read/write.
    for (int i = 0; i < tcp_clients.size(); i++) {
      if (tcp_clients[i] == NULL)
        continue;
      pfds[socket_count].fd = tcp_clients[i]->sock_fd;
      pfds[socket_count].events = POLLIN;
      tcp_clients[i]->poll_index = socket_count;

      if (tcp_clients[i]->bytes_to_send > 0) {
        pfds[socket_count].events |= POLLOUT;
      }
      socket_count += 1;
    }

    if ((ret = poll(pfds, socket_count, timeout)) == -1) {
      perror("poll");
      break;
    }

    // Nothing ready to receive from poll!
    if (ret == 0) {
      //std::cout << "No file descriptors ready from polling!" << std::endl;
      // If nothing is ready, just start over. Note the timeout will cause the CPU
      // to not just spin crazily trying to poll over and over again.
      continue;
    }

    //std::cout << ret << " file descriptors ready to do something!" << std::endl;
    if (pfds[0].revents & POLLIN) {
      //std::cout << "Ready to accept on tcp_socket!" << std::endl;
      struct TCPClient *new_tcp_client = (struct TCPClient *)malloc(sizeof(struct TCPClient));
      memset(new_tcp_client, 0, sizeof(struct TCPClient));
      client_address_len = sizeof(struct sockaddr_in);
      new_tcp_client->sock_fd = accept(tcp_socket, (struct sockaddr *)&client_address, &client_address_len);
      if (new_tcp_client->sock_fd == -1) {
        perror("accept");
        free(new_tcp_client);
      }
      else {
        memcpy(&new_tcp_client->client_address, &client_address, client_address_len);
        tcp_clients.push_back(new_tcp_client);
        std::cout << "Accepted connection from : " << get_network_address(&new_tcp_client->client_address, new_tcp_client->bytes_to_read) << "\n";
        continue;
      }
    }

    char temp_receive_buff[2048];
    if (pfds[1].revents & POLLIN) {
      std::cout << "Data has been entered." << std::endl;
      ret = read(pfds[1].fd, temp_receive_buff, 2048);
      temp_receive_buff[ret] = '\0';
      std::cout << "Read " << temp_receive_buff << " from user.\n";
    }


    for (int i = 0; i < tcp_clients.size(); i++) {
      if (tcp_clients[i] == NULL)
        continue;

      if (pfds[tcp_clients[i]->poll_index].revents & POLLIN) {
        //std::cout << "Ready to read from socket fd " << tcp_clients[i]->sock_fd << std::endl;
        ret = recv(tcp_clients[i]->sock_fd, tcp_clients[i]->recv_buf, RECEIVE_BUF_SIZE, 0);
        if (ret == -1) {
          perror("recv");
        } else if (ret == 0) { // Socket shutdown
          close(tcp_clients[i]->sock_fd);
          std::cout << "Client " << get_network_address(&tcp_clients[i]->client_address, tcp_clients[i]->client_address_len) << " disconnected.\n";
          free(tcp_clients[i]);
          tcp_clients[i] = NULL;
          continue;
        }
        else {
          std::cout << "Read " << ret << " bytes from client at address "
                    << get_network_address(&tcp_clients[i]->client_address, tcp_clients[i]->client_address_len)
                    << std::endl;
        }
      }

      if (tcp_clients[i] == NULL)
        continue;

      if (pfds[tcp_clients[i]->poll_index].revents & POLLOUT) {
        //std::cout << "Ready to write to socket fd " << tcp_clients[i]->sock_fd << std::endl;
        if (tcp_clients[i]->bytes_to_send > 0) {
          ret = send(tcp_clients[i]->sock_fd, tcp_clients[i]->send_buf, tcp_clients[i]->bytes_to_send, 0);
          //std::cout << "Wrote " << ret << " bytes on fd " << tcp_clients[i]->sock_fd << std::endl;
          if (ret == tcp_clients[i]->bytes_to_send) {
            tcp_clients[i]->bytes_to_send = 0;
          }
        }
      }

      if ((pfds[tcp_clients[i]->poll_index].revents & POLLERR)) {
        std::cout << "Got a POLLERR exception on socket fd " << tcp_clients[i]->sock_fd << std::endl;
      }

      if ((pfds[tcp_clients[i]->poll_index].revents & POLLHUP)) {
        std::cout << "Got a POLLHUP exception on socket fd " << tcp_clients[i]->sock_fd << std::endl;
      }
    }
  }


  close(client_socket);
  close(tcp_socket);
  return 0;
}




