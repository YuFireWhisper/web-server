#include "include/socket.h"

#include "include/buffer.h"
#include "include/inet_address.h"

#include <asm-generic/socket.h>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/uio.h>

namespace {
constexpr int TEMPORARY_SLEEP_MS = 100;
} // namespace

namespace server {

SocketException::SocketException(const std::string &operation)
    : std::runtime_error(operation + " failed") {}

SocketException::SocketException(const std::string &operation, int errorCode)
    : std::runtime_error(operation + " failed: " + std::strerror(errorCode)) {}

Socket::Socket()
    : socketFd_(createTcpSocket()) {}

Socket::Socket(int socketFd)
    : socketFd_(socketFd) {
  if (socketFd_ < 0) {
    throw SocketException("Socket creation");
  }
}

Socket::~Socket() {
  ::close(socketFd_);
}

int Socket::createTcpSocket() {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
  if (fd < 0) {
    throw SocketException("Socket creation", errno);
  }
  return fd;
}

void Socket::bindToPort(uint16_t port) const {
  InetAddress address(port);
  bindToAddress(address);
}

void Socket::bindToAddress(const InetAddress &address) const {
  int result = ::bind(socketFd_, address.getSockAddr(), address.getSockLen());
  if (result < 0) {
    throw SocketException("Socket bind", errno);
  }
}

void Socket::startListening(int backlog) const {
  int result = ::listen(socketFd_, backlog);
  if (result < 0) {
    throw SocketException("Socket listen", errno);
  }
}

Socket Socket::acceptNewConnection() const {
  while (true) {
    int newFd = ::accept4(socketFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (newFd >= 0) {
      return Socket(newFd);
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      std::this_thread::sleep_for(std::chrono::milliseconds(TEMPORARY_SLEEP_MS));
      continue;
    }

    throw SocketException("Socket accept", errno);
  }
}

void Socket::setSocketFlag(int level, int flag, bool enabled) const {
  int value = enabled ? 1 : 0;
  int result = ::setsockopt(socketFd_, level, flag, &value, sizeof(value));
  if (result < 0) {
    throw SocketException("Socket flag configuration", errno);
  }
}

void Socket::enableAddressReuse() {
  setSocketFlag(SOL_SOCKET, SO_REUSEADDR, true);
}

void Socket::enablePortReuse() {
  setSocketFlag(SOL_SOCKET, SO_REUSEPORT, true);
}

void Socket::enableKeepAlive() {
  setSocketFlag(SOL_SOCKET, SO_KEEPALIVE, true);
}

void Socket::disableNagle() {
  setSocketFlag(IPPROTO_TCP, TCP_NODELAY, true);
}

void Socket::configureBlockingMode(bool shouldBlock) const {
  int flags = fcntl(socketFd_, F_GETFL, 0);
  if (flags < 0) {
    throw SocketException("Get socket flags", errno);
  }

  flags = shouldBlock ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);

  int result = fcntl(socketFd_, F_SETFL, flags);
  if (result < 0) {
    throw SocketException("Set socket flags", errno);
  }
}

void Socket::enableNonBlocking() {
  configureBlockingMode(false);
}

void Socket::closeWriteEnd() const {
  int result = ::shutdown(socketFd_, SHUT_WR);
  if (result < 0) {
    throw SocketException("Socket shutdown", errno);
  }
}

Socket::ConnectionInfo Socket::getConnectionInfo() const {
  struct tcp_info rawInfo;
  socklen_t len = sizeof(rawInfo);

  int result = ::getsockopt(socketFd_, SOL_TCP, TCP_INFO, &rawInfo, &len);
  if (result < 0) {
    throw SocketException("Get connection info", errno);
  }

  return ConnectionInfo{
      .stateCode = rawInfo.tcpi_state,
      .rtt = rawInfo.tcpi_rtt,
      .rttVar = rawInfo.tcpi_rttvar,
      .congestionWindow = rawInfo.tcpi_snd_cwnd,
      .retransmits = rawInfo.tcpi_retransmits,
      .totalRetransmits = rawInfo.tcpi_total_retrans
  };
}

InetAddress Socket::getLocalAddress() const {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);

  int result = ::getsockname(socketFd_, reinterpret_cast<sockaddr *>(&addr), &len);
  if (result < 0) {
    throw SocketException("Get local address", errno);
  }

  return InetAddress(addr);
}

InetAddress Socket::getRemoteAddress() const {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);

  int result = ::getpeername(socketFd_, reinterpret_cast<sockaddr *>(&addr), &len);
  if (result < 0) {
    throw SocketException("Get remote address", errno);
  }

  return InetAddress(addr);
}

bool Socket::hasActiveConnection() const {
  try {
    return getConnectionInfo().stateCode == TCP_ESTABLISHED;
  } catch (const SocketException &) {
    return false;
  }
}

int Socket::getLastError() const {
  int error = 0;
  socklen_t len = sizeof(error);
  ::getsockopt(socketFd_, SOL_SOCKET, SO_ERROR, &error, &len);
  return error;
}

bool Socket::hasError() const {
  return getLastError() != 0;
}

size_t Socket::readData(Buffer &targetBuffer) const {
  int savedErrno = 0;
  ssize_t bytesRead = targetBuffer.readData(socketFd_, &savedErrno);

  if (bytesRead < 0) {
    if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK || savedErrno == EINTR) {
      return 0;
    }
    throw SocketException("Socket read", savedErrno);
  }

  return bytesRead;
}

size_t Socket::writeData(const Buffer &sourceBuffer) const {
  return writeData(sourceBuffer.peek(), sourceBuffer.readableBytes());
}

size_t Socket::writeData(const void *dataPtr, size_t dataLength) const {
  size_t bytesSent = 0;
  const char *currentPtr = static_cast<const char *>(dataPtr);

  while (bytesSent < dataLength) {
    ssize_t result = ::write(socketFd_, currentPtr + bytesSent, dataLength - bytesSent);

    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      throw SocketException("Socket write", errno);
    }

    bytesSent += result;
  }

  return bytesSent;
}

} // namespace server
