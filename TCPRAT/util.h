//
// Created by jurgen on 11/14/21.
//

#ifndef MINI_PROJECT2_UTIL_H
#define MINI_PROJECT2_UTIL_H
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

#endif //MINI_PROJECT2_UTIL_H
