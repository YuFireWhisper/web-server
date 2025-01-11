#pragma once

#include "include/types.h"

#include <cstddef>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <stdexcept>
#include <string>

namespace server {

class SocketException : public std::runtime_error {
public:
  explicit SocketException(const std::string &operation);
  explicit SocketException(const std::string &operation, int errorCode);
  explicit SocketException(const std::string &operation, unsigned long sslError);
};

class Buffer;
class InetAddress;

class Socket {
public:
  Socket();
  explicit Socket(int socketFd);
  ~Socket();

  Socket(const Socket &)            = delete;
  Socket &operator=(const Socket &) = delete;

  void bindToPort(uint16_t port) const;
  void bindToAddress(const InetAddress &address) const;
  void startListening(int backlog) const;
  [[nodiscard]] int acceptNewConnection(sockaddr_in &addr) const;
  [[deprecated]] [[nodiscard]] Socket acceptNewConnection() const;

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

  void attachFd(int fd);
  int detachFd();

  void initializeSSL(const std::string &certFile, const std::string &keyFile);
  bool trySSLAccept();
  void connectSSL();
  void shutdownSSL();
  static void setupSSLInfoCallback();
  static bool loadCertificateAndKey(const std::string &certFile, const std::string &keyFile);

  [[nodiscard]] bool isSSLEnabled() const { return ssl_ != nullptr; }
  [[nodiscard]] SSL *getSSL() const { return ssl_.get(); }
  [[nodiscard]] bool isSSLConnected() const;

private:
  static int createTcpSocket();
  void setSocketFlag(int level, int flag, bool enabled) const;
  void configureBlockingMode(bool shouldBlock) const;
  [[nodiscard]] int getLastError() const;
  static void initializeSSLContext();
  void handleSSLError(const std::string &operation, int result) const;
  [[nodiscard]] bool waitForSSLOperation(int result, const std::string &operation) const;
  size_t handleSSLRead(Buffer &targetBuffer) const;
  size_t handleSSLWrite(const void *dataPtr, size_t dataLength) const;

  int socketFd_;
  UniqueSSL ssl_ = nullptr;
  inline static std::atomic<SharedSslCtx> sslContext_;
  inline static std::mutex sslContextMutex_;
};

} // namespace server
