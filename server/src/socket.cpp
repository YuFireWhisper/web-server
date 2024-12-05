#include "include/socket.h"

#include "include/buffer.h"
#include "include/inter_address.h"

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
constexpr int EXTRA_BUFFER_SIZE = 65536;
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

void Socket::bindToPort(uint16_t port) {
  InterAddress address(port);
  bindToAddress(address);
}

void Socket::bindToAddress(const InterAddress &address) {
  int result = ::bind(socketFd_, address.getSockAddr(), address.getSockLen());
  if (result < 0) {
    throw SocketException("Socket bind", errno);
  }
}

void Socket::startListening(int backlog) {
  int result = ::listen(socketFd_, backlog);
  if (result < 0) {
    throw SocketException("Socket listen", errno);
  }
}

Socket Socket::acceptNewConnection() {
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

void Socket::setSocketFlag(int level, int flag, bool enabled) {
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

void Socket::configureBlockingMode(bool shouldBlock) {
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

void Socket::closeWriteEnd() {
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
      rawInfo.tcpi_state,
      rawInfo.tcpi_rtt,
      rawInfo.tcpi_rttvar,
      rawInfo.tcpi_snd_cwnd,
      rawInfo.tcpi_retransmits,
      rawInfo.tcpi_total_retrans
  };
}

InterAddress Socket::getLocalAddress() const {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);

  int result = ::getsockname(socketFd_, reinterpret_cast<sockaddr *>(&addr), &len);
  if (result < 0) {
    throw SocketException("Get local address", errno);
  }

  return InterAddress(addr);
}

InterAddress Socket::getRemoteAddress() const {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);

  int result = ::getpeername(socketFd_, reinterpret_cast<sockaddr *>(&addr), &len);
  if (result < 0) {
    throw SocketException("Get remote address", errno);
  }

  return InterAddress(addr);
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

size_t Socket::readData(Buffer &targetBuffer) {
  char extraBuffer[EXTRA_BUFFER_SIZE];
  struct iovec vec[2];

  const size_t mainSpace = targetBuffer.writableBytes();
  vec[0].iov_base = targetBuffer.beginWrite();
  vec[0].iov_len = mainSpace;
  vec[1].iov_base = extraBuffer;
  vec[1].iov_len = sizeof(extraBuffer);

  const int vectorCount = (mainSpace < sizeof(extraBuffer)) ? 2 : 1;
  const ssize_t bytesRead = ::readv(socketFd_, vec, vectorCount);

  if (bytesRead < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      return 0;
    }
    throw SocketException("Socket read", errno);
  }

  if (static_cast<size_t>(bytesRead) <= mainSpace) {
    targetBuffer.hasWritten(bytesRead);
  } else {
    targetBuffer.hasWritten(mainSpace);
    targetBuffer.append(extraBuffer, bytesRead - mainSpace);
  }

  return bytesRead;
}

size_t Socket::writeData(const Buffer &sourceBuffer) {
  return writeData(sourceBuffer.peek(), sourceBuffer.readableBytes());
}

size_t Socket::writeData(const void *dataPtr, size_t dataLength) {
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
