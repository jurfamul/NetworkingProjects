//
// Created by Nathan Evans on 10/5/21.
//

#ifndef MINI_PROJECT2_RAT_H
#define MINI_PROJECT2_RAT_H

#include <stdint.h>

/* RAT Protocol message types.
 * RATHeader.type should be set to one of these.
 * NBO expected.
 */
enum MsgType {
    RAT_REQUEST = 4000,
    RAT_REPLY = 4001,
};

/* RAT Protocol client request types.
 * RATRequest.req_type should be set to one of these.
 * NBO expected.
 */
enum RequestType {
    REQUEST_LIST_FILES = 4020,
    REQUEST_PWD = 4021,
    REQUEST_CHANGE_DIR = 4022,
    REQUEST_EXECUTE_COMMAND = 4023,
    REQUEST_SHOW_HISTORY = 4024
};

/* RAT Protocol server response types.
 * RATResponse.response_type should be set to one of these.
 * NBO expected.
 */
enum ResponseType {
    RESPONSE_ERROR = 4040,
    RESPONSE_OK = 4041
};

/**
 * RAT protocol header. Every RAT message sent/received should start with this header.
 * type should be one of MsgType, and total_msg_size should be the size of the entire
 * message, including the header, message (request or response) and any additional
 * string data.
 */
struct RATHeader {
    uint16_t type;
    uint16_t total_msg_size;
};

/**
 * A RAT request. Sent from the client to the server.
 * req_type is one of the enum RequestType's
 * argument_length is the length in bytes of string data following this struct in memory
 * request_id is a random 32bit number to correlate a request with its response
 */
struct RATRequest {
    struct RATHeader hdr;
    uint16_t req_type;
    uint16_t argument_length;
    uint32_t request_id;
    /* Optional argument data follows */
};

/**
 * A RAT response. Sent from the server to the client.
 * response_type is one of the enum ResponseType's
 * argument_length is the length in bytes of string data following this struct in memory
 * request_id is a random 32bit number to correlate a request with its response
 */
struct RATResponse {
    struct RATHeader hdr;
    uint16_t response_type;
    uint16_t data_length;
    uint32_t request_id;
    /* Optional argument data follows */
};

#endif //MINI_PROJECT2_RAT_H
