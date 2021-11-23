//
// Created by nate a long time ago
//

#ifndef CLASS_BASED_TCP_EXAMPLE_TCPCLIENT_H
#define CLASS_BASED_TCP_EXAMPLE_TCPCLIENT_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_BUFFER_SIZE 4096

class TCPClient {
public:
  TCPClient() {
    socket_fd = 0;
    memset(&client_addr, 0, sizeof(struct sockaddr_storage));
    memset(&client_listen_address, 0, sizeof(struct sockaddr_storage));
    memset(send_buffer, 0, DEFAULT_BUFFER_SIZE);
    memset(recv_buffer, 0, DEFAULT_BUFFER_SIZE);
    send_buf_offset = 0;
    recv_buf_offset = 0;
  }

  TCPClient(int fd, struct sockaddr *client_address, socklen_t client_address_len) : TCPClient() {
    socket_fd = fd;
    memcpy(&client_addr, client_address, client_address_len);
    client_addr_len = client_address_len;
  }

  ~TCPClient() {
    close(socket_fd);
  }

  unsigned int bytes_ready_to_send();
  unsigned int bytes_ready_to_recv();
  int get_fd();
  bool add_send_data(char *data, unsigned int data_len);
  bool get_recv_data(char *buf, unsigned int buf_len);
  bool get_send_data(char *buf, unsigned int buf_len);
  bool add_recv_data(char *data, unsigned int data_len);
  /* Get a printable version of the client address. Non-reentrant */
  const char *get_printable_address();
  const char *get_printable_listen_address();
  void add_client_listen_address(struct sockaddr_storage *client_listen_address, socklen_t client_listen_address_length);
  struct sockaddr_storage *get_client_listen_address();

private:
  int socket_fd;
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
  struct sockaddr_storage client_listen_address;
  socklen_t client_listen_address_len;
  char send_buffer[DEFAULT_BUFFER_SIZE];
  char recv_buffer[DEFAULT_BUFFER_SIZE];
  unsigned int send_buf_offset;
  unsigned int recv_buf_offset;
};


#endif //CLASS_BASED_TCP_EXAMPLE_TCPCLIENT_H
