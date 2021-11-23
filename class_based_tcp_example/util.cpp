//
// Created by nate a long time ago.
//

#include "util.h"

std::string get_line_from_user() {
  std::string in;

  if (!std::getline(std::cin, in)) {
    in = "quit";
  }

  return in;
}

bool check_bogon(struct in_addr addr) {
  uint8_t quad_one;
  uint8_t quad_two;
  uint8_t quad_three;
  uint8_t quad_four;

  quad_one = (uint8_t) addr.s_addr;
  quad_two = (uint8_t)((addr.s_addr >> 8) & 0x0ff);
  quad_three = (uint8_t)((addr.s_addr >> 16) & 0x0ff);
  quad_four = (uint8_t)(addr.s_addr >> 24);

  if ((quad_one == 127) || (quad_one == 10) || (quad_one == 0)
      || (quad_one == 224) || (quad_one == 240))
    return true;

  //if ((quad_one == 172) && (quad_two >= 16) && (quad_two <= 31))
  //  return 1;

  if ((quad_one == 192) && (quad_two == 168))
    return true;

  if ((quad_one == 169) && (quad_two >= 254))
    return true;

  return false;
}

bool same_address(struct sockaddr_storage *first_address, struct sockaddr_storage *second_address) {
  struct sockaddr_in *v4_first;
  struct sockaddr_in6 *v6_first;
  struct sockaddr_in *v4_second;
  struct sockaddr_in6 *v6_second;
  // Different family, different address.

  if (first_address == NULL) {
#if DEBUG
    std::cerr << "first_address is NULL, come on..." << std::endl;
#endif
    return true;
  }
  if (second_address == NULL) {
#if DEBUG
    std::cerr << "second_address is NULL, come on..." << std::endl;
#endif
    return true;
  }

  if (first_address->ss_family != second_address->ss_family) {
#if DEBUG
    std::cerr << "Addresses have different families!" << std::endl;
#endif
    return false;
  }

  if (first_address->ss_family == AF_INET) {
    v4_first = (struct sockaddr_in *) first_address;
    v4_second = (struct sockaddr_in *) second_address;

    if ((memcmp(&v4_first->sin_addr, &v4_second->sin_addr, sizeof(in_addr)) == 0) &&
        (v4_first->sin_port == v4_second->sin_port))
      return true;
  } else if (first_address->ss_family == AF_INET6) {
    v6_first = (struct sockaddr_in6 *) first_address;
    v6_second = (struct sockaddr_in6 *) second_address;
    if ((memcmp(&v6_first->sin6_addr, &v6_second->sin6_addr, sizeof(in6_addr)) == 0) &&
        (v6_first->sin6_port == v6_second->sin6_port))
      return true;
  } else {
#if DEBUG
    std::cerr << "Unknown family for addresses!" << std::endl;
#endif
  }
  // This will work as long as the address structures were zeroed out at first (is this true?)
  if (memcmp(first_address, second_address, sizeof(struct sockaddr_storage)) == 0) {
    return true;
  }
  return false;
}

const char *printable_address(struct sockaddr_storage *client_addr, socklen_t client_addr_len) {
  // Buffer will be big enough for either a v4 or v6 address
  // AND big enough to put :65535 (the port) at the end.
  static char print_buf[NI_MAXHOST + NI_MAXSERV];
  static char host_buf[NI_MAXHOST];
  static char port_buf[NI_MAXSERV];

  int ret;
  // Verify address family is either v4 or v6
  switch (client_addr->ss_family) {
    case AF_INET:
      break;
    case AF_INET6:
      break;
    default:
      return nullptr;
  }

  // If we get here, we're good to go!
  ret = getnameinfo((struct sockaddr *)client_addr, client_addr_len,
                    host_buf, NI_MAXHOST,
                    port_buf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
  if (ret != 0) {
    std::cout << "getnameinfo error " << gai_strerror(errno) << std::endl;
    return nullptr;
  }

  strncpy(print_buf, host_buf, NI_MAXHOST);
  print_buf[strlen(host_buf)] = ':';
  strncpy(&print_buf[strlen(host_buf) + 1], port_buf, NI_MAXSERV);

  return print_buf;
}
