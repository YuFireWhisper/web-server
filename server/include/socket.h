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

  void bindToPort(uint16_t port);
  void bindToAddress(const InetAddress &address);
  void startListening(int backlog);
  Socket acceptNewConnection();

  void enableAddressReuse();
  void enablePortReuse();
  void enableKeepAlive();
  void disableNagle();
  void enableNonBlocking();

  void closeWriteEnd();

  int getSocketFd() const { return socketFd_; }

  struct ConnectionInfo {
    uint32_t stateCode;
    uint32_t rtt;
    uint32_t rttVar;
    uint32_t congestionWindow;
    uint32_t retransmits;
    uint32_t totalRetransmits;
  };

  ConnectionInfo getConnectionInfo() const;
  InetAddress getLocalAddress() const;
  InetAddress getRemoteAddress() const;

  bool hasActiveConnection() const;
  bool hasError() const;

  size_t readData(Buffer &targetBuffer);
  size_t writeData(const Buffer &sourceBuffer);
  size_t writeData(const void *dataPtr, size_t dataLength);

private:
  const int socketFd_;

  static int createTcpSocket();
  void setSocketFlag(int level, int flag, bool enabled);
  void configureBlockingMode(bool shouldBlock);
  int getLastError() const;
};

} // namespace server
