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

int create_server_socket(int port) {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "Failed to create server socket\n";
    return -1;
  }

  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    close(server_fd);
    return -1;
  }

  return server_fd;
}

bool bind_socket(int server_fd, int port) {
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port " << port << "\n";
    return false;
  }

  return true;
}

bool start_listening(int server_fd, int backlog) {
  if (listen(server_fd, backlog) != 0) {
    std::cerr << "listen failed\n";
    return false;
  }
  return true;
}

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

std::string extract_echo_message(const std::string& request_target) {
  const std::string prefix = "/echo/";
  if (request_target.substr(0, prefix.length()) == prefix) {
    return request_target.substr(prefix.length());
  }
  return "";
}

void handle_request(int sock_fd, const std::string& http_request) {
  if (http_request.empty()) {
    std::cerr << "Failed to extract request target" << std::endl;
    return;
  }

  std::string request_target = extract_request_target(http_request);

  if (request_target.empty()) {
    std::cerr << "Failed to extract request target" << std::endl;
    return;
  }

  std::cout << "Request Target: " << request_target << std::endl;

  // Construct the response message
  std::string response;
  if (request_target == "/") {
    response = "HTTP/1.1 200 OK\r\n\r\n";
  } else if (request_target.find("/echo/") == 0) {
    std::string message = extract_echo_message(request_target);

    response = "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/plain\r\n"
               "Content-Length: " + std::to_string(message.length()) + "\r\n\r\n" +
               message;
  } else {
    response = "HTTP/1.1 404 Not Found\r\n\r\n";
  }

  // Send the response message
  if (send(sock_fd, response.c_str(), response.size(), 0) < 0) {
    std::cerr << "Failed to send response" << std::endl;
  }
}

int main(int argc, char **argv) {
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  
  int port = 4221;
  int backlog = 5;

  int server_fd = create_server_socket(port);
  if (server_fd < 0) return 1;

  if (!bind_socket(server_fd, port)) {
    close(server_fd);
    return 1;
  }

  if (!start_listening(server_fd, backlog)) {
    close(server_fd);
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

  handle_request(sock_fd, http_request);

  close(sock_fd);
  close(server_fd);

  return 0;
}
