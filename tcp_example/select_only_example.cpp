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
#include "util.h"


/**
 *
 * Example of using select without networking
 *
 * @param argc count of arguments on the command line
 * @param argv array of command line arguments
 * @return 0 on success, non-zero if an error occurred
 */
int main(int argc, char *argv[]) {

  // Variable used to check return codes from various functions
  int ret;

  // Select variables
  // Maximum file descriptor of those we need to select on
  int max_fds;
  // set of fds ready to read
  fd_set read_set;
  // set of fds ready to write
  fd_set write_set;
  // set of fds with exceptions
  fd_set except_set;
  // Timeout value for select
  struct timeval tv;

  // Timeout after two seconds
  tv.tv_sec = 2;
  tv.tv_usec = 0;

  int std_in_fd = 0;
  char recv_buf[DEFAULT_BUF_SIZE];

  while (true) {
    // Empty out the read set (for incoming data on socket)
    FD_ZERO(&read_set);
    // Empty out the write set (for outgoing data on socket)
    FD_ZERO(&write_set);
    // Empty out the except set (for errors/exceptions on socket)
    FD_ZERO(&except_set);

    // Set fd 0 (stdin) for checking if data has been entered
    FD_SET(std_in_fd, &read_set);
    max_fds = std_in_fd + 1;

    if ((ret = select(max_fds + 1, &read_set, &write_set, &except_set, &tv)) == -1) {
      perror("select");
      break;
    }

    // Nothing ready to receive on select!
    if (ret == 0) {
      std::cout << "No file descriptors ready in select!" << std::endl;
      continue;
    }

    //std::cout << ret << " file descriptors ready to do something!" << std::endl;
    if (FD_ISSET(std_in_fd, &read_set)) {
      std::cout << "Ready to read on standard in!" << std::endl;
      ret = read(std_in_fd, recv_buf, DEFAULT_BUF_SIZE - 1);
      std::cout << "Read " << ret << " bytes on standard in!" << std::endl;
      recv_buf[ret] = '\0';
      std::cout << "Read " << recv_buf << " from standard in" << std::endl;
    }

    // This check is to see if this FD is in the write-ready set
    if (FD_ISSET(std_in_fd, &write_set)) {
      //std::cout << "Ready to write to socket fd " << tcp_clients[i]->sock_fd << std::endl;
    }

    // This check is to see if this FD is in the exception set
    if (FD_ISSET(std_in_fd, &except_set)) {
        std::cout << "Got an exception on socket fd " << std_in_fd << std::endl;
    }

  }

  return 0;
}



