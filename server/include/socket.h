#pragma once

#include "include/types.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <string_view>

namespace server {

class SocketError final : public std::runtime_error {
public:
  explicit SocketError(std::string_view operation);
  SocketError(std::string_view operation, std::string_view details);
  SocketError(std::string_view operation, int errorCode);
  SocketError(std::string_view operation, unsigned long sslError);
};

class Buffer;
class InetAddress;

class Socket final {
public:
  Socket();
  explicit Socket(int socketFd);
  ~Socket();

  Socket(const Socket &)            = delete;
  Socket &operator=(const Socket &) = delete;
  Socket(Socket &&)                 = delete;
  Socket &operator=(Socket &&)      = delete;

  struct ConnInfo {
    uint32_t stateCode;
    uint32_t rtt;
    uint32_t rttVar;
    uint32_t congestionWindow;
    uint32_t retransmits;
    uint32_t totalRetransmits;
  };

  void bindToAddress(const InetAddress &address) const;
  void bindToPort(uint16_t port) const;
  void startListening(int backlog) const;
  [[nodiscard]] int acceptConnection(sockaddr_in &addr) const;

  void enableAddressReuse() const;
  void enablePortReuse() const;
  void enableKeepAlive() const;
  void disableNagle() const;
  void enableNonBlocking() const;
  void closeWriteEnd() const;
  void shutdownSSL();

  [[nodiscard]] int fd() const noexcept { return socketFd_; }
  [[nodiscard]] ConnInfo getConnInfo() const;
  [[nodiscard]] InetAddress getLocalAddress() const;
  [[nodiscard]] InetAddress getRemoteAddress() const;
  [[nodiscard]] bool hasActiveConnection() const noexcept;
  [[nodiscard]] bool hasError() const noexcept;

  size_t read(Buffer &buffer) const;
  size_t write(const Buffer &buffer) const;
  size_t write(const void *data, size_t length) const;

  void attachFd(int fd) noexcept;
  int detachFd() noexcept;

  void initSSL(std::string_view certFile, std::string_view keyFile);
  bool trySSLAccept() const;
  void connectSSL() const;

  [[nodiscard]] bool isSSLEnabled() const noexcept { return ssl_ != nullptr; }
  [[nodiscard]] SSL *getSSL() const noexcept { return ssl_.get(); }
  [[nodiscard]] bool isSSLConnected() const noexcept;

private:
  static constexpr size_t kIoVecCount = 16;
  static constexpr size_t kBufferSize = 16384;

  [[nodiscard]] static int createTcpSocket();
  void setSocketOption(int level, int option, int value) const;
  void setBlockingMode(bool blocking) const;
  [[nodiscard]] int getLastError() const noexcept;

  static void initSSLContext();
  void handleSSLError(std::string_view operation, int result) const;
  [[nodiscard]] bool waitForSSLOperation(int result, std::string_view operation) const;
  
  size_t readWithSSL(Buffer &buffer) const;
  size_t writeWithSSL(const void *data, size_t length) const;
  static void setupSSLCallback();
  static bool loadCertAndKey(std::string_view certFile, std::string_view keyFile);

  int socketFd_;
  UniqueSSL ssl_;
  mutable std::array<char, kBufferSize> readBuffer_;
  mutable std::array<iovec, kIoVecCount> ioVec_;
  
  inline static std::atomic<SharedSslCtx> sslContext_;
  inline static std::mutex sslMutex_;
};

} // namespace server
