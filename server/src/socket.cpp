#include "include/socket.h"

#include "include/log.h"

#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <bits/types/struct_iovec.h>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

namespace server {
Socket::Socket(int domain) {
  fd_ = ::socket(domain, SOCK_STREAM, 0);
  if (fd_ < 0) {
    Logger::log(LogLevel::ERROR, "Socket creation failed", "socket.log");
  }
}

Socket::~Socket() {
  close();
}

void Socket::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

bool Socket::bind(const std::string &ip, int port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip.c_str());

  return ::bind(fd_, (struct sockaddr *)&addr, sizeof(addr)) == 0;
}

bool Socket::listen(int backlog) {
  return ::listen(fd_, backlog) == 0;
}

std::unique_ptr<Socket> Socket::accept() {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  int connfd = ::accept(fd_, (struct sockaddr *)&addr, &len);

  if (connfd >= 0) {
    return std::make_unique<Socket>(connfd);
  }

  return nullptr;
}

bool Socket::setNonBlocking() {
  int flags = fcntl(fd_, F_GETFL, 0);
  if (flags < 0)
    return false;
  flags |= O_NONBLOCK;
  return fcntl(fd_, F_SETFL, flags) == 0;
}

bool Socket::setReuseAddr() {
  int optval = 1;
  return setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == 0;
}

bool Socket::setReusePort() {
  int optval = 1;
  return setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == 0;
}

bool Socket::setKeepAlive() {
  int optval = 1;
  return setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) == 0;
}

ssize_t Socket::read(Buffer &buffer) {
  char extrabuf[65536];
  struct iovec vec[2];
  const size_t writable = buffer.writableBytes();
  vec[0].iov_base = buffer.beginWrite();
  vec[0].iov_len = writable;
  vec[1].iov_base = extrabuf;
  vec[1].iov_len = sizeof(extrabuf);

  const ssize_t n = readv(fd_, vec, 2);
  if (n < 0) {
    return n;
  } else if (static_cast<size_t>(n) <= writable) {
    buffer.hasWritten(n);
  } else {
    buffer.hasWritten(writable);
    buffer.append(extrabuf, n - writable);
  }

  return n;
}

ssize_t Socket::write(const Buffer &buffer) {
  return ::write(fd_, buffer.peek(), buffer.writableBytes());
}

int Socket::getFd() const {
  return fd_;
};
} // namespace server
