//
// Created by Nathan Evans on 10/6/21.
//

#ifndef MINI_PROJECT1_UTIL_H
#define MINI_PROJECT1_UTIL_H

/***
 * Get a string representation (IP:PORT) of a sockaddr_in or sockaddr_in6 address.
 * This function is not re-entrant!
 *
 * @param address pointer to valid memory for a sockaddr_in or sockaddr_in6
 * @param addr_len length of address structure
 * @return pointer to string representation of address (safe to print, but not re-entrant)
 */
const char *get_network_address(struct sockaddr *address, socklen_t addr_len);

#endif //MINI_PROJECT1_UTIL_H
