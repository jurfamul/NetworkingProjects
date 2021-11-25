//
// Created by jurgen on 11/14/21.
//
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>

#include "util.h"

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

int execute_command_get_response(const char *cmd, const char **return_buffer) {
    FILE *file_pointer;
    // max size for the command buffer
    static char cmd_buf[MAX_CMD_BUFFER];
    int bytes_read;

    // Execute a command in a shell, then get a file handle to the result data.
    // Be very careful with this, it's easy for someone to do something nasty!
    file_pointer = popen(cmd, "r");
    if (file_pointer == NULL) {
        handle_error("popen");
        std::cerr << "Failed to execute command: " << cmd << std::endl;
        (*return_buffer) = NULL;
        return 0;
    }

    // Read the output from the command into our buffer. If it's too big, truncate it.
    bytes_read = fread(cmd_buf, 1, MAX_CMD_BUFFER, file_pointer);

    if (bytes_read <= 0) {
        std::cerr << "Failed to read any bytes from command pipe? ret was " << bytes_read << std::endl;
        handle_error("fgets");
        (*return_buffer) = NULL;
        return 0;
    }

    std::cout << "Read " << bytes_read << " bytes of output from command " << cmd << std::endl;
    std::cout << "Read data was: " << cmd_buf << std::endl;
    cmd_buf[bytes_read] = '\0';
    (*return_buffer) = cmd_buf;
    // Close it, using pclose since we used popen!
    pclose(file_pointer);
    return bytes_read;
}


