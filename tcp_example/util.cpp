//
// Created by Nathan Evans on 10/6/21.
//

#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>

void handle_error(const char *context) {
  std::cerr << context << " failed with error:" << std::endl;
  std::cerr << strerror(errno) << std::endl;
  return;
}

const char *get_network_address(struct sockaddr *address, socklen_t addr_len) {
  static char dest[INET6_ADDRSTRLEN + 7];
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;
  uint16_t port;
  const char *result_address;

  if (address->sa_family == AF_INET) {
    v4 = (struct sockaddr_in *)address;
    result_address = inet_ntop(address->sa_family, &v4->sin_addr, dest, sizeof(struct sockaddr_in));
    port = ntohs(v4->sin_port);
  } else if (address->sa_family == AF_INET6) {
    v6 = (struct sockaddr_in6 *)address;
    result_address = inet_ntop(address->sa_family, &v6->sin6_addr, dest, sizeof(struct sockaddr_in6));
    port = ntohs(v6->sin6_port);
  }

  int i = 0;
  while (i < (INET6_ADDRSTRLEN + 7) && (dest[i] != '\0')) {
    i++;
  }
  if (i <= INET6_ADDRSTRLEN) {
    snprintf(&dest[i], 7, ":%u", port);
    if (result_address != NULL)
      return dest;
  }

  return NULL;
}

