//
// Created by Nathan Evans on 10/20/21.
//

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
#include <poll.h>

#include "util.h"

#define MAX_POLL_FDS 500

/**
 *
 * Example of using poll without networking.
 *
 * @param argc count of arguments on the command line
 * @param argv array of command line arguments
 * @return 0 on success, non-zero if an error occurred
 */
int main(int argc, char *argv[]) {
  // Variable used to check return codes from various functions
  int ret;

  struct pollfd pfds[MAX_POLL_FDS];

  int poll_timeout;

  int timeout;
  timeout = 2000;

  // Check if connecting succeeded at all
  if (ret != 0) {
    std::cout << "Failed to bind to any addresses!" << std::endl;
    return 1;
  }

  int std_in_fd = 0;
  int stdin_pfds_index;

  while (true) {
    nfds_t socket_count = 0;

    // Checking for incoming data on STDIN
    pfds[socket_count].fd = std_in_fd;
    pfds[socket_count].events = POLLIN | POLLOUT;
    stdin_pfds_index = socket_count;
    socket_count += 1;

    // We need to set up the pfds array for every socket/fd we need to check!

    if ((ret = poll(pfds, socket_count, timeout)) == -1) {
      perror("poll");
      break;
    }

    // Nothing ready to receive from poll!
    if (ret == 0) {
      std::cout << "No file descriptors ready from polling!" << std::endl;
      // If nothing is ready, just start over. Note the timeout will cause the CPU
      // to not just spin crazily trying to poll over and over again.
      continue;
    }

    char temp_receive_buff[DEFAULT_BUF_SIZE];
    if (pfds[stdin_pfds_index].revents & POLLIN) {
      std::cout << "Data has been entered." << std::endl;
      ret = read(pfds[stdin_pfds_index].fd, temp_receive_buff, DEFAULT_BUF_SIZE - 1);
      temp_receive_buff[ret] = '\0';
      std::cout << "Read " << temp_receive_buff << " from user.\n";
    }

    if ((pfds[stdin_pfds_index].revents & POLLERR)) {
      std::cout << "Got a POLLERR exception on socket fd " << std_in_fd << std::endl;
    }

    if ((pfds[stdin_pfds_index].revents & POLLHUP)) {
      std::cout << "Got a POLLHUP exception on socket fd " << std_in_fd << std::endl;
    }
  }

  return 0;
}





