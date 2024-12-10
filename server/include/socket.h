#pragma once

#include <cstddef>
#include <netinet/tcp.h>
#include <stdexcept>
#include <string>

namespace server {

class SocketException : public std::runtime_error {
public:
  explicit SocketException(const std::string &operation);
  explicit SocketException(const std::string &operation, int errorCode);
};

class Buffer;
class InetAddress;

class Socket {
public:
  Socket();
  explicit Socket(int socketFd);
  ~Socket();

  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;

  void bindToPort(uint16_t port) const;
  void bindToAddress(const InetAddress &address) const;
  void startListening(int backlog) const;
  [[nodiscard]] Socket acceptNewConnection() const;

  void enableAddressReuse();
  void enablePortReuse();
  void enableKeepAlive();
  void disableNagle();
  void enableNonBlocking();

  void closeWriteEnd() const;

  [[nodiscard]] int getSocketFd() const { return socketFd_; }

  struct ConnectionInfo {
    uint32_t stateCode;
    uint32_t rtt;
    uint32_t rttVar;
    uint32_t congestionWindow;
    uint32_t retransmits;
    uint32_t totalRetransmits;
  };

  [[nodiscard]] ConnectionInfo getConnectionInfo() const;
  [[nodiscard]] InetAddress getLocalAddress() const;
  [[nodiscard]] InetAddress getRemoteAddress() const;

  [[nodiscard]] bool hasActiveConnection() const;
  [[nodiscard]] bool hasError() const;

  size_t readData(Buffer &targetBuffer) const;
  [[nodiscard]] size_t writeData(const Buffer &sourceBuffer) const;
  size_t writeData(const void *dataPtr, size_t dataLength) const;

private:
  const int socketFd_;

  static int createTcpSocket();
  void setSocketFlag(int level, int flag, bool enabled) const;
  void configureBlockingMode(bool shouldBlock) const;
  [[nodiscard]] int getLastError() const;
};

} // namespace server
