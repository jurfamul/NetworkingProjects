//
// Created by Nathan Evans on 10/6/21.
//

#ifndef SIMPLE_UDP_2021_UTIL_H
#define SIMPLE_UDP_2021_UTIL_H

#define DEFAULT_BUF_SIZE 2048

/***
 * Generic error handler. Just a shortcut. Prints out the strerror from errno,
 * along with whatever the context provided was.
 * @param context a printable char * string with any context of where the error occurred
 */
void handle_error(const char *context);

/***
 * Get a string representation (IP:PORT) of a sockaddr_in or sockaddr_in6 address.
 * This function is not re-entrant!
 *
 * @param address pointer to valid memory for a sockaddr_in or sockaddr_in6
 * @param addr_len length of address structure
 * @return pointer to string representation of address (safe to print, but not re-entrant)
 */
const char *get_network_address(struct sockaddr *address, socklen_t addr_len);

#endif //SIMPLE_UDP_2021_UTIL_H
