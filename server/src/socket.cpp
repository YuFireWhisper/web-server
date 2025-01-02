#include "include/socket.h"

#include "include/buffer.h"
#include "include/inet_address.h"
#include "include/log.h"

#include <asm-generic/socket.h>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
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

SocketException::SocketException(const std::string &operation, unsigned long sslError)
    : std::runtime_error([&operation, sslError]() {
      char errBuf[256];
      ERR_error_string_n(sslError, errBuf, sizeof(errBuf));
      return operation + ": " + errBuf;
    }()) {}

Socket::Socket()
    : socketFd_(createTcpSocket()) {}

Socket::Socket(int socketFd)
    : socketFd_(socketFd) {
  LOG_DEBUG("創建新的 Socket，fd=" + std::to_string(socketFd_));
  if (socketFd_ < 0) {
    throw SocketException("Socket creation");
  }
}

SSL_CTX *Socket::sslContext_ = nullptr;

Socket::~Socket() {
  if (ssl_) {
    SSL_shutdown(ssl_.get());
  }
  LOG_DEBUG("關閉 Socket，fd=" + std::to_string(socketFd_));
  ::close(socketFd_);
}

void Socket::initializeSSLContext() {
  if (sslContext_ != nullptr) {
    return;
  }

  const SSL_METHOD *method = TLS_method();
  if (method == nullptr) {
    throw SocketException("SSL method initialization", ERR_get_error());
  }

  sslContext_ = SSL_CTX_new(method);
  if (sslContext_ == nullptr) {
    throw SocketException("SSL context initialization", ERR_get_error());
  }

  SSL_CTX_set_mode(sslContext_, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_options(sslContext_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
}

void Socket::handleSSLError(const std::string &operation, int result) const {
  int sslError          = SSL_get_error(ssl_.get(), result);
  unsigned long errCode = ERR_get_error();

  std::string errorMsg = operation + " failed: ";
  if (errCode != 0) {
    char errBuf[256];
    ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
    errorMsg += errBuf;
  } else {
    switch (sslError) {
      case SSL_ERROR_WANT_READ:
        errorMsg += "需要更多數據讀取";
        break;
      case SSL_ERROR_WANT_WRITE:
        errorMsg += "需要更多數據寫入";
        break;
      case SSL_ERROR_SYSCALL:
        errorMsg += "系統錯誤: " + std::string(strerror(errno));
        break;
      case SSL_ERROR_SSL:
        errorMsg += "協議錯誤";
        break;
      default:
        errorMsg += "未知錯誤";
        break;
    }
  }

  throw SocketException(errorMsg, errCode);
}

size_t Socket::handleSSLRead(Buffer &buffer) const {
  if (!ssl_) {
    throw SocketException("SSL not initialized");
  }

  size_t totalBytes = 0;
  char tempBuffer[4096];

  while (true) {
    int bytes = SSL_read(ssl_.get(), tempBuffer, sizeof(tempBuffer));
    if (bytes <= 0) {
      int err = SSL_get_error(ssl_.get(), bytes);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        break; // 需要更多數據
      }
      if (bytes < 0) {
        handleSSLError("SSL read", bytes);
      }
      break;
    }

    buffer.write(tempBuffer, bytes);
    totalBytes += bytes;
  }

  return totalBytes;
}

size_t Socket::handleSSLWrite(const void *dataPtr, size_t dataLength) const {
  if (!ssl_) {
    throw SocketException("SSL not initialized");
  }

  size_t totalWritten = 0;
  const char *ptr     = static_cast<const char *>(dataPtr);

  while (totalWritten < dataLength) {
    int written =
        SSL_write(ssl_.get(), ptr + totalWritten, static_cast<int>(dataLength - totalWritten));
    if (written <= 0) {
      int err = SSL_get_error(ssl_.get(), written);
      if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
        break;
      }
      handleSSLError("SSL write", written);
    }
    totalWritten += written;
  }

  return totalWritten;
}

void Socket::initializeSSL(const std::string &certFile, const std::string &keyFile) {
  if (sslContext_ == nullptr) {
    initializeSSLContext();
  }

  ssl_.reset(SSL_new(sslContext_));
  if (!ssl_) {
    throw SocketException("SSL initialization", ERR_get_error());
  }

  if (SSL_use_certificate_file(ssl_.get(), certFile.c_str(), SSL_FILETYPE_PEM) != 1) {
    throw SocketException("SSL certificate loading", ERR_get_error());
  }

  if (SSL_use_PrivateKey_file(ssl_.get(), keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
    throw SocketException("SSL private key loading", ERR_get_error());
  }

  if (SSL_set_fd(ssl_.get(), socketFd_) != 1) {
    throw SocketException("SSL fd setting", ERR_get_error());
  }
}

void Socket::acceptSSL() {
  if (!ssl_) {
    throw SocketException("SSL not initialized");
  }

  int result = SSL_accept(ssl_.get());
  if (result != 1) {
    handleSSLError("SSL accept", result);
  }
}

void Socket::connectSSL() {
  if (!ssl_) {
    throw SocketException("SSL not initialized");
  }

  int result = SSL_connect(ssl_.get());
  if (result != 1) {
    handleSSLError("SSL connect", result);
  }
}

int Socket::createTcpSocket() {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
  if (fd < 0) {
    throw SocketException("Socket creation", errno);
  }
  return fd;
}

void Socket::bindToPort(uint16_t port) const {
  InetAddress address(AF_INET, "0.0.0.0", port);
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
  int value  = enabled ? 1 : 0;
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

  return ConnectionInfo{ .stateCode        = rawInfo.tcpi_state,
                         .rtt              = rawInfo.tcpi_rtt,
                         .rttVar           = rawInfo.tcpi_rttvar,
                         .congestionWindow = rawInfo.tcpi_snd_cwnd,
                         .retransmits      = rawInfo.tcpi_retransmits,
                         .totalRetransmits = rawInfo.tcpi_total_retrans };
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
  int error     = 0;
  socklen_t len = sizeof(error);
  ::getsockopt(socketFd_, SOL_SOCKET, SO_ERROR, &error, &len);
  return error;
}

bool Socket::hasError() const {
  return getLastError() != 0;
}

size_t Socket::readData(Buffer &targetBuffer) const {
  if (ssl_) {
    return handleSSLRead(targetBuffer);
  }

  int savedErrno    = 0;
  ssize_t bytesRead = targetBuffer.readFromFd(socketFd_, &savedErrno);

  if (bytesRead < 0) {
    if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK || savedErrno == EINTR) {
      return 0;
    }
    throw SocketException("Socket read", savedErrno);
  }

  return bytesRead;
}

size_t Socket::writeData(const Buffer &sourceBuffer) const {
  size_t readable = sourceBuffer.readableSize();
  return writeData(sourceBuffer.preview(readable).data(), readable);
}

size_t Socket::writeData(const void *dataPtr, size_t dataLength) const {
  if (ssl_) {
    return handleSSLWrite(dataPtr, dataLength);
  }

  size_t bytesSent       = 0;
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

void Socket::attachFd(int fd) {
  if (socketFd_ >= 0) {
    ::close(socketFd_);
  }
  socketFd_ = fd;
  LOG_DEBUG("Socket 附加到 fd=" + std::to_string(fd));
}

int Socket::detachFd() {
  int fd    = socketFd_;
  socketFd_ = -1;
  return fd;
}

} // namespace server
