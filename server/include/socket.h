#pragma once

#include <include/buffer.h>
#include <memory>

#include <sys/socket.h>
#include <sys/types.h>

namespace server {
class Socket {
public:
  Socket(int domain = AF_INET);
  ~Socket();

  bool bind(const std::string &ip, int port);
  bool listen(int backlog = SOMAXCONN);
  std::unique_ptr<Socket> accept();

  bool setNonBlocking();
  bool setReuseAddr();
  bool setReusePort();
  bool setKeepAlive();

  ssize_t read(Buffer &buffer);
  ssize_t write(const Buffer &buffer);

  int getFd() const;

private:
  int fd_;
  void close();
};

} // namespace server
