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
#include <unordered_map>
#include <thread>

#include <optional>
#include <CLI/CLI.hpp>

#include <filesystem>

#include <tuple>

namespace fs = std::filesystem;

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

std::tuple<std::string, std::string> parse_route(const std::string& http_request) {
    std::istringstream request_stream(http_request);
    std::string method, request_target, http_version;

    // Parse the first line of the HTTP request
    if (request_stream >> method >> request_target >> http_version) {
        return std::make_tuple(method, request_target);
    }

    return std::make_tuple("", "");
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

std::string extract_second_level_route(const std::string& prefix, const std::string& request_target) {
  if (request_target.substr(0, prefix.length()) == prefix) {
    return request_target.substr(prefix.length());
  }
  return "";
}

std::string extract_echo_message(const std::string& request_target) {
  const std::string prefix = "/echo/";
  return extract_second_level_route(prefix, request_target);
}

std::string extract_filename(const std::string& request_target) {
  const std::string prefix = "/files/";
  return extract_second_level_route(prefix, request_target);
}

std::unordered_map<std::string, std::string> extract_headers(const std::string& http_request) {
  std::unordered_map<std::string, std::string> headers;

  // Find the end of the headers section
  size_t headers_end = http_request.find("\r\n\r\n");
  if (headers_end == std::string::npos) {
    std::cerr << "Invalid HTTP request format: no headers found.\n";
    return headers;
  }

  // Extract headers substring
  std::string headers_str = http_request.substr(0, headers_end);

  // Split headers into lines
  std::istringstream headers_stream(headers_str);
  std::string line;
  while (std::getline(headers_stream, line)) {
    // Skip empty lines
    if (line.empty() || line == "\r") continue;

    // Find the separator ":"
    size_t delimiter_pos = line.find(':');
    if (delimiter_pos == std::string::npos) continue;

    // Extract header name and value
    std::string header_name = line.substr(0, delimiter_pos);
    std::string header_value = line.substr(delimiter_pos + 1);

    // Trim leading and trailing whitespaces
    header_name.erase(header_name.find_last_not_of(" \t") + 1);
    header_name.erase(0, header_name.find_first_not_of(" \t"));
    header_value.erase(header_value.find_last_not_of(" \t") + 1);
    header_value.erase(0, header_value.find_first_not_of(" \t"));

    // Insert header into the map
    headers[header_name] = header_value;
  }

  return headers;
}

// forward decl
bool is_readable(const std::string& path);

std::string build_files_response(std::string directory, std::string filename) {
  if (!is_readable(directory)) {
    std::cout << std::filesystem::current_path() << "is unreadable" << std::endl;
    return "HTTP/1.1 500 Directory unreadable\r\n\r\n";
  }

  // Join directory and filename
  fs::path file_path = fs::path(directory) / filename;

  // Check if file exists and is readable
  if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
    // Return 404 Not Found if file does not exist
    return "HTTP/1.1 404 Not Found\r\n\r\n";
  }

  // Read file contents
  std::ifstream file(file_path, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    // Return 404 Not Found if file cannot be opened
    return "HTTP/1.1 404 Not Found\r\n\r\n";
  }

  // Get file size
  std::streamsize file_size = file.tellg();
  file.seekg(0, std::ios::beg);

  // Read file contents into a vector of bytes
  std::vector<char> file_contents(file_size);
  if (!file.read(file_contents.data(), file_size)) {
    // Return 404 Not Found if file cannot be read
    return "HTTP/1.1 404 Not Found\r\n\r\n";
  }

  // Construct HTTP response
  std::stringstream response;
  response << "HTTP/1.1 200 OK\r\n";
  response << "Content-Length: " << file_size << "\r\n";
  response << "Content-Type: application/octet-stream\r\n"; // Set the content type to application/octet-stream
  response << "\r\n"; // End of headers

  // Convert the response stream to a string and append the file contents
  std::string response_str = response.str();
  response_str.insert(response_str.end(), file_contents.begin(), file_contents.end());

  return response_str;
}

std::string handle_get_requests(const std::string& request_target, std::unordered_map<std::string, std::string> headers, std::optional<std::string> maybe_directory) {
  std::string response;

  if (request_target == "/") {
    response = "HTTP/1.1 200 OK\r\n\r\n";
  } else if (request_target.find("/echo/") == 0) {
    std::string message = extract_echo_message(request_target);

    response = "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/plain\r\n"
               "Content-Length: " + std::to_string(message.length()) + "\r\n\r\n" +
               message;
  } else if (request_target.find("/files/") == 0) {
    if (maybe_directory) {
      std::string directory = *maybe_directory;
      std::cout << "Directory: " << directory << std::endl;

      std::string filename = extract_filename(request_target);
      response = build_files_response(directory, filename);
    } else {
      response = "HTTP/1.1 500 Directory not set on server\r\n\r\n";
    }
  } else if (request_target == "/user-agent") {
    std::string message = headers["User-Agent"];
    response = "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/plain\r\n"
               "Content-Length: " + std::to_string(message.length()) + "\r\n\r\n" +
               message;
  } else {
    response = "HTTP/1.1 404 Not Found\r\n\r\n";
  }

  return response;
}

bool save_file(std::string directory, std::string filename, std::string body) {
  try {
    fs::create_directories(directory);

    fs::path file_path = fs::path(directory) / filename;

    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
      std::cerr << "Failed to open file: " << file_path << std::endl;
      return false;
    }

    file.write(body.c_str(), body.size());

    if (!file) {
      std::cerr << "Failed to write to file: " << file_path << std::endl;
      return false;
    }

    return true;
  } catch (const std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
    return false;
  }
}

std::string handle_post_requests(
        const std::string& request_target,
        std::unordered_map<std::string, std::string> headers,
        std::string body,
        std::optional<std::string> maybe_directory
    ) {
  std::string response;

  if (request_target.find("/files/") == 0) {
    if (maybe_directory) {
      std::string directory = *maybe_directory;
      std::cout << "Directory: " << directory << std::endl;

      std::string filename = extract_filename(request_target);
      if (save_file(directory, filename, body)) {
        response = "HTTP/1.1 201 Created\r\n\r\n";
      } else {
        response = "HTTP/1.1 500 Couldn't save file\r\n\r\n";
      }
    } else {
      response = "HTTP/1.1 500 Directory not set on server\r\n\r\n";
    }
  } else {
    response = "HTTP/1.1 404 Not Found\r\n\r\n";
  }

  return response;
}

std::string get_body(const std::string& http_request, const std::unordered_map<std::string, std::string>& headers) {
  auto it = headers.find("Content-Length");
  if (it == headers.end()) {
    return "";
  }

  int content_length = std::stoi(it->second);

  size_t body_pos = http_request.find("\r\n\r\n");
  if (body_pos == std::string::npos) {
    return "";
  }
  body_pos += 4;

  if (body_pos + content_length <= http_request.size()) {
    return http_request.substr(body_pos, content_length);
  } else {
    return "";
  }
}

void check_and_add_content_encoding(std::unordered_map<std::string, std::string>& headers,
                                    std::unordered_map<std::string, std::string>& response_headers) {
  auto it = headers.find("Accept-Encoding");
  if (it != headers.end() && it->second.find("gzip") != std::string::npos) {
    response_headers["Content-Encoding"] = "gzip";
  }
}

std::string get_first_line(const std::string& http_response) {
  size_t end_of_first_line = http_response.find("\r\n");
  if (end_of_first_line != std::string::npos) {
    return http_response.substr(0, end_of_first_line);
  } else {
    return "";
  }
}

std::string build_http_response(
        const std::string& first_line,
        const std::unordered_map<std::string, std::string>& headers,
        const std::string& body
    ) {

  std::stringstream response;

  response << first_line << "\r\n";

  for (const auto& header : headers) {
    response << header.first << ": " << header.second << "\r\n";
  }

  response << "\r\n";

  response << body;

  return response.str();
}

void handle_request(int sock_fd, const std::string& http_request, std::optional<std::string> maybe_directory) {
  if (http_request.empty()) {
    std::cerr << "Failed to extract request target" << std::endl;
    return;
  }

  auto [method, request_target] = parse_route(http_request);

  auto headers = extract_headers(http_request);

  for (const auto& [key, value] : headers) {
    std::cout << key << ": " << value << std::endl;
  }

  if (request_target.empty()) {
    std::cerr << "Failed to extract request target" << std::endl;
    return;
  }

  std::cout << "Method: " << method << std::endl;
  std::cout << "Request Target: " << request_target << std::endl;

  std::string response;
  if (method == "GET") {
    response = handle_get_requests(request_target, headers, maybe_directory);
  } else if (method == "POST") {
    std::string body = get_body(http_request, headers);
    response = handle_post_requests(request_target, headers, body, maybe_directory);
  } else {
    response = "HTTP/1.1 404 Not Found\r\n\r\n";
  }
  auto response_headers = extract_headers(response);

  std::string first_line = get_first_line(response);
  check_and_add_content_encoding(headers, response_headers);
  std::string body = get_body(response, response_headers);

  response = build_http_response(first_line, response_headers, body);

  // Send the response message
  if (send(sock_fd, response.c_str(), response.size(), 0) < 0) {
    std::cerr << "Failed to send response" << std::endl;
  }
}

bool is_readable(const std::string& path) {
  try {
    fs::path dir_path(path);

    return fs::exists(dir_path) && fs::is_directory(dir_path);
  } catch (const fs::filesystem_error& e) {
      std::cerr << "Filesystem error: " << e.what() << std::endl;
  }

  return false;
}

int main(int argc, char **argv) {
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  CLI::App app{"Simple Webserver"};

  std::optional<std::string> maybe_directory;
  app.add_option("--directory", maybe_directory, "Directory from which to serve files");

  CLI11_PARSE(app, argc, argv);

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

  auto f = [maybe_directory](int sock_fd, struct sockaddr_in client_addr, socklen_t client_addr_len) {

    std::string http_request = receive_data(sock_fd, client_addr, client_addr_len);
    if (!http_request.empty())
      handle_request(sock_fd, http_request, maybe_directory);
    close(sock_fd);
  };

  int sock_fd;

  std::vector<std::thread> threads;
 
  while (true) {
    sock_fd = accept(
        server_fd,
        (struct sockaddr *) &client_addr,
        (socklen_t *) &client_addr_len
    );

    threads.emplace_back(f, sock_fd, client_addr, client_addr_len);

  }
  for (auto& t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }

  close(server_fd);

  return 0;
}
