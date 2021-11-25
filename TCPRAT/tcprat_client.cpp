//
// Created by jurgen on 11/07/21.
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
#include "RAT.h"

#define MAX_POLL_FDS 500

/***
 * Send a list files request to a UDP RAT server.
 *
 * @param socket the socket to send data on (UDP)
 * @param server_address the server destination address
 * @return the number of bytes sent, or -1 on error.
 */
int send_list_files(int socket, int id) {
    int bytes_sent;
    std::cout << "request id is " << id << std::endl;

    struct RATRequest ls_request;
    ls_request.hdr.type = htons(RAT_REQUEST);
    ls_request.hdr.total_msg_size = htons(sizeof(struct RATRequest));
    ls_request.req_type = htons(REQUEST_LIST_FILES);
    ls_request.request_id = htonl(id);
    ls_request.argument_length = htons(0);

    bytes_sent = send(socket, &ls_request, sizeof(struct RATRequest), 0);
    return bytes_sent;
}

int send_pwd(int socket, int id)
{
    int bytes_sent;

    struct RATRequest pwd_request;
    pwd_request.hdr.type = htons(RAT_REQUEST);
    pwd_request.hdr.total_msg_size = htons(sizeof(struct RATRequest));
    pwd_request.req_type = htons(REQUEST_PWD);
    pwd_request.request_id = htonl(id);
    pwd_request.argument_length = htons(0);

    bytes_sent = send(socket, &pwd_request, sizeof(struct RATRequest), 0);
    return bytes_sent;
}

int send_change_dir(int socket, char *arg_string, int id)
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


    bytes_sent = send(socket, &message_buff, message_size, 0);
    return bytes_sent;
}

int send_execute_cmd(int socket, char *arg_string, int id)
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

    bytes_sent = send(socket, &message_buff, message_size, 0);
    return bytes_sent;
}

int send_show_history(int socket, int id)
{
    int bytes_sent;

    struct RATRequest pwd_request;
    pwd_request.hdr.type = htons(RAT_REQUEST);
    pwd_request.hdr.total_msg_size = htons(sizeof(struct RATRequest));
    pwd_request.req_type = htons(REQUEST_SHOW_HISTORY);
    pwd_request.request_id = htonl(id);
    pwd_request.argument_length = htons(0);

    bytes_sent = send(socket, &pwd_request, sizeof(struct RATRequest), 0);
    return bytes_sent;
}

int main(int argc, char *argv[]) {
    // Variable used to check return codes from various functions
    int ret;
    /* alias for command line argument for ip address */
    char *ip_string;
    /* alias for command line argument for port */
    char *port_string;
    // alias for command line argument string to send the rat command to server
    char *command_string;
    // alias for command line argument string to send the rat argument string to the server
    char *arg_string;
    /* tcp_socket will be the socket used for sending/receiving */
    int tcp_socket;
    // The type of request specified on the client command line.
    uint16_t request_type;

    // Variable for the ipv4 server address
    struct sockaddr_in server_address;
    // Variable for the ipv4 server address length
    socklen_t server_address_len;

    /* buffer to use for receiving data */
    static char recv_buf[DEFAULT_BUF_SIZE];

    if (argc < 3) {
        std::cerr << "Provide IP PORT to connect to as first two arguments." << std::endl;
        return 1;
    }
    /* assign ip_str to the first command line argument */
    ip_string = argv[1];
    /* assign port_str to the second command line argument */
    port_string = argv[2];

    // 1. Create the socket
    tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // 2. Connect the socket to the server.
    // First need to look up a suitable address for the server
    // (may need to do a DNS lookup first!)

    // hints are things we want the returned address to match
    struct addrinfo hints;
    // results is where our list of addresses will be stored
    struct addrinfo *results;
    // results_it is just a pointer to iterate over the list in results
    struct addrinfo *results_it;
    // set hints to all zeroes, these are the "defaults" for the values
    memset(&hints, 0, sizeof(struct addrinfo));
    // Specify we want only ipv4 addresses
    hints.ai_family = AF_INET;
    // Specify that we want a TCP capable address
    hints.ai_socktype = SOCK_STREAM;
    // There are other members of hints that we don't need right now. man getaddrvinfo for details!

    // getaddrinfo will take our hostname, port number and hints, and return a list of compatible addresses
    // these addresses (in results) will be of the correct type for bind or connect.
    ret = getaddrinfo(ip_string, port_string, &hints, &results);

    if (ret != 0) {
        handle_error("getaddrinfo");
        return -1;
    }

    // results_it is an "interator" element for our results
    // results is a list of addresses that match our specifications
    results_it = results;
    ret = -1;
    while (results_it != NULL) {
        std::cout << "Attempting to CONNECT to " <<
                  get_network_address(results_it->ai_addr, results_it->ai_addrlen) << std::endl;

        // Actually connect to the server!
        ret = connect(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
        if (ret == 0) // Success
        {
            break;
        }
        ret = -1;
        handle_error("connect");
        // ai_next points to the next element in the linked list of results.
        // if NULL, it means we have reached the end
        results_it = results_it->ai_next;
    }

    // Whatever happened, we need to free the address list.
    freeaddrinfo(results);

    if (ret == -1) {
        handle_error("connect failed");
        return -1;
    }

    while (true) {

        std::string input_str;
        //std::cout << "Please enter a valid server command or quit." << std::endl;
        getline(std::cin, input_str);

        if (input_str.compare("quit") == 0) {
            std::cout << "Read command quit from user." << std::endl;
            close(tcp_socket);
            return 0;
        } else {
            int space_pos = input_str.find(" ");
            if (space_pos == std::string::npos)
            {
                command_string = const_cast<char*>(input_str.data());
                arg_string = NULL;
            }
            else
            {
                command_string = const_cast<char*>(input_str.substr(0, space_pos).data());
                arg_string = const_cast<char*>(input_str.substr(space_pos+1, std::string::npos).data());
            }
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
        } else if (strncmp("history", command_string, 7) == 0) {
            request_type = REQUEST_SHOW_HISTORY;
        } else {
            std::cerr << "Unknown command " << command_string << std::endl;
            std::cerr << "Please enter a valid command, one of ls, cd, pwd, run. " << std::endl;
            return 1;
        }

        int request_id = rand();

        // Send the correct message based on the request type.
        switch (request_type) {
            case REQUEST_LIST_FILES:
                ret = send_list_files(tcp_socket, request_id);
                break;
            case REQUEST_EXECUTE_COMMAND:
                ret = send_execute_cmd(tcp_socket, arg_string, request_id);
                break;
            case REQUEST_CHANGE_DIR:
                ret = send_change_dir(tcp_socket, arg_string, request_id);
                break;
            case REQUEST_PWD:
                ret = send_pwd(tcp_socket, request_id);
                break;
            case REQUEST_SHOW_HISTORY:
                ret = send_show_history(tcp_socket, request_id);
                break;
            default:
                std::cerr << "Unknown request type?" << std::endl;
                return 1;
                break;
        }

        // If we get here, it means that we are successfully connected to a server somewhere! Yay!!!
        // That means we can send just by using the socket, as it's already connected.

        std::cout << "sent " << ret << " bytes to server" << std::endl;

        //RATResponse struct to store the RATMessage sent by the server.
        RATResponse *server_response = (RATResponse *) malloc(sizeof(struct RATResponse));
        int server_response_size = sizeof(struct RATResponse);

        // If we expect a result from the server, this is where we would get it.
        ret = recv(tcp_socket, recv_buf, DEFAULT_BUF_SIZE, 0);

        if (ret <= 0) {
            handle_error("recv");
            close(tcp_socket);
            return 1;
        }

        if (ret >= 0) {
            std::cout << ret << " bytes received from address " << std::endl;
            //Separate server's response into the RATResponse and the output string of the server operation
            memcpy(server_response, recv_buf, server_response_size);
            //extract the instance variables from the server_response struct.
            uint16_t header_type = ntohs(server_response->hdr.type);

            if (header_type == RAT_REPLY) {
                uint16_t total_response_size = ntohs(server_response->hdr.total_msg_size);

                std::cout << "Received RAT message type " << header_type << " with length " << total_response_size
                          << std::endl;
                std::cout << "Received server response type " << ntohs(server_response->response_type)
                          << " to the request id " << ntohl(server_response->request_id) << " of length "
                          << ntohs(server_response->data_length) << std::endl;

                if (ret == total_response_size) {
                    std::cout << "The server response seems legitimate. (message length and header type match)."
                              << std::endl;

                    if (request_id == ntohl(server_response->request_id)) {
                        std::cout << "The server response id matches the client request ID. Continuing." << std::endl;

                        if (ntohs(server_response->response_type) == RESPONSE_ERROR) {
                            std::cout << "Received an error response from the server. Error message is: "
                                      << std::string(recv_buf + server_response_size, ret - (server_response_size))
                                      << std::endl;
                        } else {
                            std::cout << "Received an OK response from the server. Result is: "
                                      << std::string(recv_buf + server_response_size, ret - (server_response_size))
                                      << std::endl;
                        }
                    }
                }
            }
        }
    }
}

