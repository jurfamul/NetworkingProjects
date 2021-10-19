//
// Created by jurgen on 10/16/21.
//

#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "RAT.h"
#include "util.h"
#include <stdint.h>

/***
 * Send a list files request to a UDP RAT server.
 *
 * @param socket the socket to send data on (UDP)
 * @param server_address the server destination address
 * @return the number of bytes sent, or -1 on error.
 */
int send_list_files(int socket, const struct sockaddr *server_address, int id) {
    int bytes_sent;

    struct RATRequest ls_request;
    ls_request.hdr.type = htons(RAT_REQUEST);
    ls_request.hdr.total_msg_size = htons(sizeof(struct RATRequest));
    ls_request.req_type = htons(REQUEST_LIST_FILES);
    ls_request.request_id = htonl(id);
    ls_request.argument_length = htons(0);

    bytes_sent = sendto(socket, &ls_request, sizeof(struct RATRequest), 0, server_address, sizeof(struct sockaddr_in));
    return bytes_sent;
}

int send_pwd(int socket, const struct sockaddr *server_address, int id)
{
    int bytes_sent;

    struct RATRequest pwd_request;
    pwd_request.hdr.type = htons(RAT_REQUEST);
    pwd_request.hdr.total_msg_size = htons(sizeof(struct RATRequest));
    pwd_request.req_type = htons(REQUEST_PWD);
    pwd_request.request_id = htonl(id);
    pwd_request.argument_length = htons(0);

    bytes_sent = sendto(socket, &pwd_request, sizeof(struct RATRequest), 0, server_address, sizeof(struct sockaddr_in));
    return bytes_sent;
}

int send_change_dir(int socket, const struct sockaddr *server_address, char *arg_string, int id)
{
    int bytes_sent;
    int arg_length = strlen(arg_string);
    const int message_size = sizeof(struct RATResponse) + arg_length;

    struct RATRequest cd_request;
    cd_request.hdr.type = htons(RAT_REQUEST);
    cd_request.hdr.total_msg_size = htons(message_size);
    cd_request.req_type = htons(REQUEST_CHANGE_DIR);
    cd_request.request_id = htonl(id);
    cd_request.argument_length = htons(arg_length);


    static char message_buff[2048];
    //copy the cmd_request into the message_buffer
    memcpy(message_buff, &cd_request, sizeof(struct RATRequest));
    //copy the arg_string into the message_buffer
    memcpy(message_buff+sizeof(struct RATRequest), arg_string, arg_length);


    bytes_sent = sendto(socket, &message_buff, message_size, 0, server_address, sizeof(struct sockaddr_in));
    return bytes_sent;
}

int send_execute_cmd(int socket, const struct sockaddr *server_address, char *arg_string, int id)
{
    int bytes_sent;
    int arg_length = strlen(arg_string);
    const int message_size = sizeof(struct RATResponse) + arg_length;

    struct RATRequest cmd_request;
    cmd_request.hdr.type = htons(RAT_REQUEST);
    cmd_request.hdr.total_msg_size = htons(message_size);
    cmd_request.req_type = htons(REQUEST_EXECUTE_COMMAND);
    cmd_request.request_id = htonl(id);
    cmd_request.argument_length = htons(arg_length);

    static char message_buff[2048];
    //copy the cmd_request into the message_buffer
    memcpy(message_buff, &cmd_request, sizeof(struct RATRequest));
    //copy the arg_string into the message_buffer
    memcpy(message_buff+sizeof(struct RATRequest), arg_string, arg_length);

    bytes_sent = sendto(socket, &message_buff, message_size, 0, server_address, sizeof(struct sockaddr_in));
    return bytes_sent;
}
/**
 *
 * UDP RAT client. Parses a request from the command line, then sends to the server.
 * Awaits response from server after request is sent.
 *
 * e.g., ./rat_udpclient 127.0.0.1 8888 ls
 *       ./rat_udpclient 127.0.0.1 8888 cd /root/
 *
 * @param argc count of arguments on the command line
 * @param argv array of command line arguments
 * @return 0 on success, non-zero if an error occurred
 */
int main(int argc, char *argv[]) {

    // Alias for argv[1] for convenience
    char *ip_string;

    // Alias for argv[2] for convenience
    char *port_string;

    // Alias for argv[3] for convenience
    char *command_string;

    // Alias for argv[4] for convenience
    char *arg_string;

    // Port to send UDP data to. Need to convert from command line string to a number
    unsigned int port;

    // The socket used to send UDP data on
    int udp_socket;

    // Variable used to check return codes from various functions
    int ret;

    // Buffer for sending data
    char send_buf[2048];

    // Current offset into send_buf
    int offset = 0;

    // IPv4 structure representing and IP address and port of the destination
    struct sockaddr_in dest_addr;

    // The type of request specified on the client command line.
    uint16_t request_type;

    // Set dest_addr to all zeroes, just to make sure it's not filled with junk
    // Note we could also make it a static variable, which will be zeroed before execution
    memset(&dest_addr, 0, sizeof(struct sockaddr_in));

    // Note: this needs to be at least 4, program name counts as an argument!
    if (argc < 4) {
        std::cerr << "Please specify IP PORT COMMAND [ARGUMENT] as arguments." << std::endl;
        return 1;
    }
    // Set up variables "aliases"
    ip_string = argv[1];
    port_string = argv[2];
    command_string = argv[3];
    if (argc == 5) {
        arg_string = argv[4]+'\0';
    } else {
        arg_string = NULL;
    }

    // Parse out the command given to the client.
    if (strncmp("ls", command_string, 2) == 0) {
        request_type = REQUEST_LIST_FILES;
    } else if (strncmp("cd", command_string, 2) == 0) {
        request_type = REQUEST_CHANGE_DIR;
        if (arg_string == NULL) {
            std::cerr << "This command requires an argument." << std::endl;
            return 1;
        }
    } else if (strncmp("pwd", command_string, 3) == 0) {
        request_type = REQUEST_PWD;
    } else if (strncmp("run", command_string, 3) == 0) {
        request_type = REQUEST_EXECUTE_COMMAND;
        if (arg_string == NULL) {
            std::cerr << "This command requires an argument." << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Unknown command " << command_string << std::endl;
        std::cerr << "Please enter a valid command, one of ls, cd, pwd, run. " << std::endl;
        return 1;
    }

    // Step 1: Create the UDP socket.
    // AF_INET is the address family used for IPv4 addresses
    // SOCK_DGRAM indicates creation of a UDP socket
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    // Make sure socket was created successfully, or exit.
    if (udp_socket == -1) {
        std::cerr << "Failed to create udp socket!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        return 1;
    }

    // inet_pton converts an ip address string (e.g., 1.2.3.4) into the 4 byte
    // equivalent required for using the address in code.
    // Note that because dest_addr is a sockaddr_in (IPv4) the 'sin_addr'
    // member of the struct is used for the IP
    ret = inet_pton(AF_INET, ip_string, (void *)&dest_addr.sin_addr);

    // Check whether the specified IP was parsed properly. If not, exit.
    if (ret == -1) {
        std::cerr << "Failed to parse IPv4 address!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    // Convert the port string into an unsigned integer.
    ret = sscanf(port_string, "%u", &port);
    // sscanf is called with one argument to convert, so the result should be 1
    // If not, exit.
    if (ret != 1) {
        std::cerr << "Failed to parse port!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    // Set the address family to AF_INET (IPv4)
    dest_addr.sin_family = AF_INET;
    // Set the destination port. Use htons (host to network short)
    // to ensure that the port is in big endian format
    dest_addr.sin_port = htons(port);

    int request_id = rand();

    // Send the correct message based on the request type.
    switch (request_type) {
        case REQUEST_LIST_FILES:
            ret = send_list_files(udp_socket, (struct sockaddr *)&dest_addr, request_id);
            break;
        case REQUEST_EXECUTE_COMMAND:
            ret = send_execute_cmd(udp_socket, (struct sockaddr *)&dest_addr, arg_string, request_id);
            break;
        case REQUEST_CHANGE_DIR:
            ret = send_change_dir(udp_socket, (struct sockaddr *)&dest_addr, arg_string, request_id);
            break;
        case REQUEST_PWD:
            ret = send_pwd(udp_socket, (struct sockaddr *)&dest_addr, request_id);
            break;
        default:
            std::cerr << "Unknown request type?" << std::endl;
            return 1;
            break;
    }

    // Check if send worked, clean up and exit if not.
    if (ret == -1) {
        std::cerr << "Failed to send data!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    std::cout << "Sent " << ret << " bytes out to server." << std::endl;

    /**
     * Code to receive response from the server goes here!
     * recv or recvfrom...
     */

    //stores the return value of the recvfrom function which is either the error code or the
    //length of the message received from the server.
    int rec;

    //A buffer that will store the raw response from the server.
    static char recv_buff[2048];

    int recv_buff_size = sizeof(recv_buff);

    //RATResponse struct to store the RATMessage sent by the server.
    RATResponse* server_response = (RATResponse*)malloc(sizeof(struct RATResponse));
    int server_response_size = sizeof(struct RATResponse);

    //set the size of the incoming address
    socklen_t recv_address_size = sizeof(struct sockaddr_in);

    rec = recvfrom(udp_socket, &recv_buff, recv_buff_size, 0,
                   (struct sockaddr *) &dest_addr, &recv_address_size);

    if (rec == -1) {
        std::cerr << "Failed to receive data!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    if (rec >= 0) {
        std::cout << rec << " bytes received from address " << std::endl;
        //Separate server's response into the RATResponse and the output string of the server operation
        memcpy(server_response, recv_buff, server_response_size);
        //extract the instance variables from the server_response struct.
        uint16_t header_type = ntohs(server_response->hdr.type);

        if (header_type == RAT_REPLY)
        {
            uint16_t total_response_size = ntohs(server_response->hdr.total_msg_size);

            std::cout << "Received RAT message type " <<  header_type << " with length " << total_response_size << std::endl;
            std::cout << "Received server response type " << ntohs(server_response->response_type)
                      << " to the request id " << ntohl(server_response->request_id) << " of length "
                      << ntohs(server_response->data_length) << std::endl;

            if (rec == total_response_size)
            {
                std::cout << "The server response seems legitimate. (message length and header type match)." << std::endl;

                if (request_id == ntohl(server_response->request_id))
                {
                    std::cout << "The server response id matches the client request ID. Continuing." << std::endl;

                    if (ntohs(server_response->response_type) == RESPONSE_ERROR)
                    {
                        std::cout << "Received an error response from the server. Error message is: "
                                    << std::string(recv_buff+server_response_size, rec-(server_response_size)) << std::endl;
                    }
                    else
                    {
                        std::cout << "Received an OK response from the server. Result is: "
                                    << std::string(recv_buff+server_response_size, rec-(server_response_size)) << std::endl;
                    }
                }
            }
        }
    }

    close(udp_socket);
    return 0;
}
