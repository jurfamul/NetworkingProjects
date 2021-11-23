//
// Created by nate a long time ago.
//

#ifndef CLASS_BASED_TCP_EXAMPLE_UTIL_H
#define CLASS_BASED_TCP_EXAMPLE_UTIL_H


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <vector>
#include <netdb.h>
#include <iostream>

std::string get_line_from_user();
const char *printable_address(struct sockaddr_storage *client_addr, socklen_t client_addr_len);
bool same_address(struct sockaddr_storage *first_address, struct sockaddr_storage *second_address);
bool check_bogon(struct in_addr addr);
#endif //CLASS_BASED_TCP_EXAMPLE_UTIL_H
