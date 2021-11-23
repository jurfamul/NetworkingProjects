#include "TCPServer.h"
#include "TCPClient.h"
#include "util.h"
#include <sys/select.h>

#define RECEIVE_BUF_SIZE 4096
#define SEND_BUF_SIZE 4096


int main(int argc, char *argv[]) {

  std::vector<TCPClient *> client_list;
  struct sockaddr_storage new_client;
  socklen_t incoming_client_len;
  TCPClient *temp_client;
  struct timeval timeout;
  char recv_buf[RECEIVE_BUF_SIZE];
  char send_buf[SEND_BUF_SIZE];

  bool stop = false;
  time_t curr_time;
  int ret;
  int max_fds;


  TCPServer my_server("127.0.0.1", "12345");
  my_server.start_server();


  std::cout << "Started server at " << my_server.get_printable_address() << std::endl;

  fd_set read_set;
  fd_set write_set;
  fd_set exc_set;

  while (stop == false) {
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&exc_set);

    // Set the server socket, so we can accept new connections when they come in
    FD_SET(my_server.get_server_socket(), &read_set);

      // Set each file descriptor in our vector to check if it's ready to read/write.
      for (int i = 0; i < client_list.size(); i++) {
          if (client_list[i] == NULL)
              continue;

          if (client_list[i]->get_fd() > max_fds) {
              max_fds = client_list[i]->get_fd();
          }
          //std::cout << "Checking fd " << tcp_clients[i]->get_fd() << " for readiness!" << std::endl;
          FD_SET(client_list[i]->get_fd(), &read_set);
          if (client_list[i]->bytes_ready_to_send() > 0)
              FD_SET(client_list[i]->get_fd(), &write_set);
      }

    time(&curr_time);

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    ret = select(max_fds + 1, &read_set, &write_set, &exc_set, &timeout);

    if (ret == 0) {
      // If no fd's are ready, just try again, no need to check.
      continue;
    } else if (ret == -1) {
      perror("select");
      break;
    }

    //std::cout << ret << " file descriptors ready for some action." << std::endl;

    // First check for new connections.
    if (FD_ISSET(my_server.get_server_socket(), &read_set)) {
      // Time to accept a connection.
      incoming_client_len = sizeof(struct sockaddr_storage);
      ret = my_server.accept_connection(&new_client, &incoming_client_len);
      if (ret != -1) {
        temp_client = new TCPClient(ret, (struct sockaddr *) &new_client, incoming_client_len);
        std::cerr << "Accepted connecting client from " << temp_client->get_printable_address() << std::endl;
        client_list.push_back(temp_client);
      }
    }

    // Next check if clients have sent us data
      for (int i = 0; i < client_list.size(); i++) {
          if (client_list[i] == NULL)
              continue;

          if (FD_ISSET(client_list[i]->get_fd(), &read_set)) {
              std::cout << "Ready to read from socket fd " << client_list[i]->get_fd() << std::endl;
              ret = recv(client_list[i]->get_fd(), recv_buf, RECEIVE_BUF_SIZE, 0);
              if (ret == -1) {
                  perror("recv");
              } else if (ret == 0) { // Socket shutdown
                  std::cerr << "Client " << client_list[i]->get_printable_address() << " disconnected." << std::endl;
                  close(client_list[i]->get_fd());
                  free(client_list[i]);
                  client_list[i] = NULL;
                  continue;
              }
              else {
                  // Since we're printing it out, add a terminator to the string
                  recv_buf[ret] = '\0';
                  std::cout << "Client sent: " << recv_buf << std::endl;
                  // Add data to received data list, to process later
                  client_list[i]->add_recv_data(recv_buf, ret);

                  // Add data to send data list, to send next time around
                  // This is what makes the server an "echo" server, you wouldn't
                  // want to do this generally...
                  client_list[i]->add_send_data(recv_buf, ret);
              }
          }

          if (client_list[i] == NULL)
              continue;

          if (FD_ISSET(client_list[i]->get_fd(), &write_set)) {
              if (client_list[i]->bytes_ready_to_send() > 0) {
                  int bytes_to_send = client_list[i]->bytes_ready_to_send();
                  if (client_list[i]->get_send_data(send_buf, SEND_BUF_SIZE)) {
                      ret = send(client_list[i]->get_fd(), send_buf, bytes_to_send, 0);
                      std::cout << "Wrote " << ret << " bytes on fd " << client_list[i]->get_fd() << std::endl;
                  }
              }
          }
      }

      // Here is where you would process incoming data from clients.
      // The nice part about this setup is you can send/receive data in one place,
      // and handle it/queue it to send another place.

  }
  my_server.stop_server();
}
