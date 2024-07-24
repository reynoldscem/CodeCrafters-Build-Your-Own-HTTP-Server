#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <vector>

std::string extract_request_target(const std::string& http_request) {
    std::istringstream request_stream(http_request);
    std::string method, request_target, http_version;

    // Parse the first line of the HTTP request
    if (request_stream >> method >> request_target >> http_version) {
        return request_target;
    }

    // If parsing failed, return an empty string
    return "";
}

std::string receive_data(int sockfd, sockaddr_in& client_addr, socklen_t& client_addr_len) {
  // Initial buffer size
  std::vector<char> buffer(1024);

  while (true) {
    ssize_t bytes_received = recvfrom(sockfd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&client_addr, &client_addr_len);
    if (bytes_received == -1) {
      std::cerr << "Failed to receive data" << std::endl;
      return ""; // Return empty string to indicate failure
    }

    if (static_cast<size_t>(bytes_received) < buffer.size()) {
      buffer[bytes_received] = '\0';
      return std::string(buffer.data()); // Return the received data as std::string
    } else {
        // Double the buffer size and try again
        buffer.resize(buffer.size() * 2);
    }
  }
}


int main(int argc, char **argv) {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return 1;
  }
  
  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return 1;
  }
  
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);
  
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 1;
  }
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 1;
  }
  
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  
  std::cout << "Waiting for a client to connect...\n";
  
  int sock_fd = accept(
      server_fd,
      (struct sockaddr *) &client_addr,
      (socklen_t *) &client_addr_len
  );


  std::string http_request = receive_data(sock_fd, client_addr, client_addr_len);

  if (http_request.empty()) {
      std::cerr << "Failed to extract request target" << std::endl;
  } else {
    std::string request_target = extract_request_target(http_request);

    if (!request_target.empty()) {
      std::cout << "Request Target: " << request_target << std::endl;

      const char* message;
      if (request_target == "/")
        message = "HTTP/1.1 200 OK\r\n\r\n";
      else
        message = "HTTP/1.1 404 Not Found\r\n\r\n";

      send(sock_fd, message, strlen(message), 0);
    }

  }

  std::cout << "Client connected\n";
  
  close(server_fd);

  return 0;
}
