#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void handle_error(const char *context) {
  std::cerr << context << " failed with error:" << std::endl;
  std::cerr << strerror(errno) << std::endl;
  return;
}

int main(int argc, char *argv[]) {
  // Aliases for command line arguments
  char *ip_str;
  char *port_str;

  // Socket we will use to receive and send data on the server
  int udp_socket;
  // Port we are going to bind to (converted from port_str, eventually)
  unsigned int port;
  // Need a binary address which contains the IP and Port the server will bind to
  struct sockaddr_in dest;

  // Memory location to hold incoming data sent from the client
  static char recv_buf[2048];
  // Binary address structure of the client that sent data to the server
  struct sockaddr_in recv_addr;
  // Size of the address we received data from (it could be ipv4 or ipv6, which have different sizes)
  socklen_t recv_addr_size;

  // Variable to hold/test return values of functions we called
  int ret;

  if (argc < 3) {
    std::cerr << "Provide IP PORT as first two arguments." << std::endl;
    return 1;
  }

  // Assign first command line argument to ip_str variable
  ip_str = argv[1];
  // Assign second command line argument to port_str variable
  port_str = argv[2];

  // UDP Server step 1: Create the socket (AF_INET means IPv4, SOCK_DGRAM means UDP)
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  if (udp_socket == -1) {
    std::cerr << "Failed to create socket with error:" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return 1;
  }

  // Parse the ip_str into a binary ipv4 address
  ret = inet_pton(AF_INET, ip_str, &dest.sin_addr);

  if (ret == -1) {
    handle_error("inet_pton");
    return 1;
  }

  // Convert the port_str from a string into an actual number
  ret = sscanf(port_str, "%u", &port);

  // Make sure sscanf worked
  if (ret != 1) {
    handle_error("sscanf");
  }

  // Finally, we can set up the server address structure!
  // Set the address type to IPV4 (AF_INET)
  // Set the address length to the appropriate size for an IPV4 address (sizeof(struct sockaddr_in))
  // Set the port to the network byte order of the port number
  dest.sin_family = AF_INET;
  dest.sin_len = sizeof(struct sockaddr_in);
  dest.sin_port = htons(port);

  // UDP Server Step 2: bind to the ip:port stored in dest
  ret = bind(udp_socket, (struct sockaddr *) &dest, sizeof(struct sockaddr_in));

  // Check the result of bind
  if (ret == -1) {
    handle_error("bind");
    close(udp_socket);
    return 1;
  }

  // Before receiving, set the allowed size of an incoming address. Since our recv_addr is a
  // sockaddr_in, we need to set it to the sizeof(struct sockaddr_in)
  recv_addr_size = sizeof(struct sockaddr_in);
  // UDP Server Step 3: receive data from client (this call will block until data is received or an error occurs!)
  ret = recvfrom(udp_socket, recv_buf, 2047, 0, (struct sockaddr *) &recv_addr, &recv_addr_size);

  if (ret == -1) {
    handle_error("recvfrom");
    close(udp_socket);
    return 1;
  }

  std::cout << "Received " << ret << " bytes from address size " << recv_addr_size << std::endl;
  recv_buf[ret] = '\0';
  std::cout << "Received '" << recv_buf << "'" << std::endl;

  // UDP Server Step 4: send the received data back to the client
  ret = sendto(udp_socket, recv_buf, ret, 0, (struct sockaddr *) &recv_addr, recv_addr_size);

  if (ret == -1) {
    handle_error("sendto");
    close(udp_socket);
    return 1;
  }

close(udp_socket);
return 0;
}
