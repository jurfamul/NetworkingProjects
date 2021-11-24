//
// Created by jurgen on 11/14/21.
//

#ifndef MINI_PROJECT2_SERVER_UTIL_H
#define MINI_PROJECT2_SERVER_UTIL_H

#define DEFAULT_BUF_SIZE 2048
#define MAX_CMD_BUFFER 1450

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

/***
 * Execute a command (using popen) and get the output.
 * Non-reentrant, as it uses a static buffer for the command output! If you change it to
 * callee allocated, caller freed that would make it "better", but slightly less performant.
 *
 * @param cmd the command to execute (may include arguments)
 * @param return_buffer modified by callee (this function!) to point to location of command result data
 * @return number of valid bytes in return_buffer
 */
int execute_command_get_response(const char *cmd, const char **return_buffer);



#endif //MINI_PROJECT2_SERVER_UTIL_H
