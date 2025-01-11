#include "include/socket.h"

#include "include/buffer.h"
#include "include/inet_address.h"
#include "include/log.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <openssl/err.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/uio.h>

namespace server {

SocketError::SocketError(std::string_view operation)
    : std::runtime_error(std::string(operation) + " failed") {}

SocketError::SocketError(std::string_view operation, std::string_view details)
    : std::runtime_error(std::string(operation) + ": " + std::string(details)) {}

SocketError::SocketError(std::string_view operation, int errorCode)
    : std::runtime_error(std::string(operation) + " failed: " + std::strerror(errorCode)) {}

SocketError::SocketError(std::string_view operation, unsigned long sslError)
    : std::runtime_error([&operation, sslError]() {
      char errBuf[256];
      ERR_error_string_n(sslError, errBuf, sizeof(errBuf));
      return std::string(operation) + ": " + errBuf;
    }()) {}

Socket::Socket()
    : socketFd_(createTcpSocket()) {}

Socket::Socket(int socketFd)
    : socketFd_(socketFd) {
  if (socketFd_ < 0) {
    throw SocketError("Socket creation", errno);
  }
  LOG_DEBUG("Socket created with fd=" + std::to_string(socketFd_));
}

Socket::~Socket() {
  if (ssl_) {
    SSL_shutdown(ssl_.get());
  }
  if (socketFd_ >= 0) {
    ::close(socketFd_);
    LOG_DEBUG("Socket closed, fd=" + std::to_string(socketFd_));
  }
}

int Socket::createTcpSocket() {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
  if (fd < 0) {
    throw SocketError("Socket creation", errno);
  }
  return fd;
}

void Socket::bindToPort(uint16_t port) const {
  InetAddress address(AF_INET, "0.0.0.0", port);
  bindToAddress(address);
}

void Socket::bindToAddress(const InetAddress &address) const {
  if (::bind(socketFd_, address.getSockAddr(), address.getSockLen()) < 0) {
    throw SocketError("Socket bind", errno);
  }
}

void Socket::startListening(int backlog) const {
  if (::listen(socketFd_, backlog) < 0) {
    throw SocketError("Socket listen", errno);
  }
}

int Socket::acceptConnection(sockaddr_in &addr) const {
  socklen_t len = sizeof(addr);
  return ::accept4(
      socketFd_,
      reinterpret_cast<sockaddr *>(&addr),
      &len,
      SOCK_NONBLOCK | SOCK_CLOEXEC
  );
}

void Socket::setSocketOption(int level, int option, int value) const {
  if (::setsockopt(socketFd_, level, option, &value, sizeof(value)) < 0) {
    throw SocketError("setsockopt", errno);
  }
}

void Socket::enableAddressReuse() const {
  setSocketOption(SOL_SOCKET, SO_REUSEADDR, 1);
}

void Socket::enablePortReuse() const {
  setSocketOption(SOL_SOCKET, SO_REUSEPORT, 1);
}

void Socket::enableKeepAlive() const {
  setSocketOption(SOL_SOCKET, SO_KEEPALIVE, 1);
}

void Socket::disableNagle() const {
  setSocketOption(IPPROTO_TCP, TCP_NODELAY, 1);
}

void Socket::setBlockingMode(bool blocking) const {
  int flags = ::fcntl(socketFd_, F_GETFL);
  if (flags < 0) {
    throw SocketError("fcntl(F_GETFL)", errno);
  }

  flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
  if (::fcntl(socketFd_, F_SETFL, flags) < 0) {
    throw SocketError("fcntl(F_SETFL)", errno);
  }
}

void Socket::enableNonBlocking() const {
  setBlockingMode(false);
}

void Socket::closeWriteEnd() const {
  if (::shutdown(socketFd_, SHUT_WR) < 0) {
    throw SocketError("Socket shutdown", errno);
  }
}

Socket::ConnInfo Socket::getConnInfo() const {
  tcp_info info;
  socklen_t len = sizeof(info);

  if (::getsockopt(socketFd_, SOL_TCP, TCP_INFO, &info, &len) < 0) {
    throw SocketError("Get connection info", errno);
  }

  return ConnInfo{ .stateCode        = info.tcpi_state,
                   .rtt              = info.tcpi_rtt,
                   .rttVar           = info.tcpi_rttvar,
                   .congestionWindow = info.tcpi_snd_cwnd,
                   .retransmits      = info.tcpi_retransmits,
                   .totalRetransmits = info.tcpi_total_retrans };
}

InetAddress Socket::getLocalAddress() const {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);

  if (::getsockname(socketFd_, reinterpret_cast<sockaddr *>(&addr), &len) < 0) {
    throw SocketError("Get local address", errno);
  }
  return InetAddress(addr);
}

InetAddress Socket::getRemoteAddress() const {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);

  if (::getpeername(socketFd_, reinterpret_cast<sockaddr *>(&addr), &len) < 0) {
    throw SocketError("Get remote address", errno);
  }
  return InetAddress(addr);
}

bool Socket::hasActiveConnection() const noexcept {
  try {
    return getConnInfo().stateCode == TCP_ESTABLISHED;
  } catch (const SocketError &) {
    return false;
  }
}

int Socket::getLastError() const noexcept {
  int error     = 0;
  socklen_t len = sizeof(error);
  ::getsockopt(socketFd_, SOL_SOCKET, SO_ERROR, &error, &len);
  return error;
}

bool Socket::hasError() const noexcept {
  return getLastError() != 0;
}

size_t Socket::read(Buffer &buffer) const {
  if (ssl_) {
    return readWithSSL(buffer);
  }

  constexpr size_t maxAttempts = 64;
  size_t totalRead             = 0;
  size_t attempts              = 0;

  while (attempts++ < maxAttempts) {
    ssize_t n = ::read(socketFd_, readBuffer_.data(), readBuffer_.size());
    if (n > 0) {
      buffer.write(readBuffer_.data(), static_cast<size_t>(n));
      totalRead += static_cast<size_t>(n);
      if (static_cast<size_t>(n) < readBuffer_.size()) {
        break;
      }
    } else if (n == 0) {
      break;
    } else if (errno != EINTR) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      throw SocketError("Socket read", errno);
    }
  }

  return totalRead;
}

size_t Socket::write(const Buffer &buffer) const {
  return write(buffer.preview(buffer.readableSize()).data(), buffer.readableSize());
}

size_t Socket::write(const void *data, size_t length) const {
  if (ssl_) {
    return writeWithSSL(data, length);
  }

  size_t remaining = length;
  const char *ptr  = static_cast<const char *>(data);

  while (remaining > 0) {
    ssize_t n = ::write(socketFd_, ptr, remaining);
    if (n > 0) {
      ptr += n;
      remaining -= static_cast<size_t>(n);
    } else if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      throw SocketError("Socket write", errno);
    }
  }

  return length - remaining;
}

void Socket::attachFd(int fd) noexcept {
  if (socketFd_ >= 0) {
    ::close(socketFd_);
  }
  socketFd_ = fd;
  LOG_DEBUG("Socket attached to fd=" + std::to_string(socketFd_));
}

int Socket::detachFd() noexcept {
  int fd    = socketFd_;
  socketFd_ = -1;
  return fd;
}

void Socket::initSSLContext() {
  std::lock_guard<std::mutex> lock(sslMutex_);

  SharedSslCtx current = sslContext_.load(std::memory_order_acquire);
  if (current != nullptr) {
    return;
  }

  const SSL_METHOD *method = TLS_method();
  if (method == nullptr) {
    throw SocketError("SSL method initialization", ERR_get_error());
  }

  SSL_CTX *ctx = SSL_CTX_new(method);
  if (ctx == nullptr) {
    throw SocketError("SSL context initialization", ERR_get_error());
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
  SSL_CTX_set_session_id_context(ctx, (const unsigned char *)&ksessionCtxId, sizeof(ksessionCtxId));

  constexpr int sslOptions = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION
                             | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
                             | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_SINGLE_DH_USE
                             | SSL_OP_SINGLE_ECDH_USE;

  SSL_CTX_set_options(ctx, sslOptions);

  SharedSslCtx newContext(ctx, SSLCtxDeleter{});
  sslContext_.store(newContext, std::memory_order_release);
}

void Socket::initSSL(std::string_view certFile, std::string_view keyFile) {
  LOG_TRACE("Initializing SSL for socket " + std::to_string(socketFd_));

  SharedSslCtx ctx = sslContext_.load(std::memory_order_acquire);
  if (ctx == nullptr) {
    initSSLContext();
    ctx = sslContext_.load(std::memory_order_acquire);
  }

  UniqueSSL tempSSL(SSL_new(ctx.get()));
  if (tempSSL == nullptr) {
    throw SocketError("SSL initialization", ERR_get_error());
  }

  if (SSL_set_fd(tempSSL.get(), socketFd_) != 1) {
    throw SocketError("SSL fd setting", ERR_get_error());
  }

  ssl_ = std::move(tempSSL);

  loadCertAndKey(certFile, keyFile);

  setupSSLCallback();
  LOG_TRACE("SSL initialized successfully");
}

bool Socket::trySSLAccept() const {
  if (ssl_ == nullptr) {
    throw SocketError("SSL not initialized");
  }

  int result = SSL_accept(ssl_.get());
  if (result == 1) {
    LOG_INFO("SSL accept successful");
    return true;
  }

  int sslError = SSL_get_error(ssl_.get(), result);
  if (sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE) {
    return false;
  }

  handleSSLError("SSL accept", result);
  return false;
}

size_t Socket::writeWithSSL(const void *data, size_t length) const {
  if (ssl_ == nullptr) {
    throw SocketError("SSL not initialized");
  }

  size_t written  = 0;
  const auto *ptr = static_cast<const char *>(data);

  while (written < length) {
    int n = SSL_write(ssl_.get(), ptr + written, static_cast<int>(length - written));
    if (n <= 0) {
      int err = SSL_get_error(ssl_.get(), n);
      if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
        break;
      }
      handleSSLError("SSL write", n);
    }
    written += static_cast<size_t>(n);
  }

  return written;
}

size_t Socket::readWithSSL(Buffer &buffer) const {
  if (ssl_ == nullptr) {
    throw SocketError("SSL not initialized");
  }

  size_t totalBytes = 0;
  int n             = 0;

  do {
    n = SSL_read(ssl_.get(), readBuffer_.data(), static_cast<int>(readBuffer_.size()));
    if (n > 0) {
      buffer.write(readBuffer_.data(), static_cast<size_t>(n));
      totalBytes += static_cast<size_t>(n);
    } else if (n < 0) {
      int err = SSL_get_error(ssl_.get(), n);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        handleSSLError("SSL read", n);
      }
      break;
    }
  } while (static_cast<size_t>(n) == readBuffer_.size());

  return totalBytes;
}

void Socket::handleSSLError(std::string_view operation, int result) const {
  int sslError          = SSL_get_error(ssl_.get(), result);
  unsigned long errCode = ERR_get_error();

  if (sslError == SSL_ERROR_SYSCALL && result == 0) {
    throw SocketError(operation, "EOF occurred in violation of protocol");
  }

  std::string errorDetails;
  char errBuf[256];

  do {
    ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
    if (!errorDetails.empty()) {
      errorDetails += ", ";
    }
    errorDetails += errBuf;
  } while ((errCode = ERR_get_error()) != 0);

  throw SocketError(operation, errorDetails);
}

void Socket::connectSSL() const {
  if (ssl_ == nullptr) {
    throw SocketError("SSL not initialized");
  }

  while (true) {
    int result = SSL_connect(ssl_.get());
    if (result == 1) {
      return;
    }

    int err = SSL_get_error(ssl_.get(), result);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      handleSSLError("SSL connect", result);
    }
  }
}

void Socket::shutdownSSL() {
  if (ssl_ != nullptr) {
    SSL_shutdown(ssl_.get());
    ssl_.reset();
  }
}

bool Socket::isSSLConnected() const noexcept {
  return ssl_ != nullptr && (SSL_is_init_finished(ssl_.get()) != 0);
}

void Socket::setupSSLCallback() {
  SharedSslCtx ctx = sslContext_.load(std::memory_order_acquire);
  if (ctx == nullptr) {
    throw SocketError("SSL context not initialized");
  }

  SSL_CTX_set_info_callback(ctx.get(), [](const SSL *ssl, int where, int ret) {
    const char *operation;
    if (where & SSL_ST_CONNECT) {
      operation = "connect";
    } else if (where & SSL_ST_ACCEPT) {
      operation = "accept";
    } else {
      operation = "undefined";
    }

    if (where & SSL_CB_LOOP) {
      LOG_DEBUG(std::string(operation) + ": " + SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
      const char *direction = (where & SSL_CB_READ) ? "read" : "write";
      LOG_DEBUG(
          "SSL alert " + std::string(direction) + ": " + SSL_alert_type_string_long(ret) + ": "
          + SSL_alert_desc_string_long(ret)
      );
    }
  });
}

bool Socket::loadCertAndKey(std::string_view certFile, std::string_view keyFile) {
  std::lock_guard<std::mutex> lock(sslMutex_);

  SharedSslCtx ctx = sslContext_.load(std::memory_order_acquire);
  if (ctx == nullptr) {
    throw SocketError("SSL context not initialized");
  }

  if (SSL_CTX_use_certificate_chain_file(ctx.get(), std::string(certFile).c_str()) != 1) {
    LOG_ERROR("Failed to load certificate chain: " + std::to_string(ERR_get_error()));
    return false;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx.get(), std::string(keyFile).c_str(), SSL_FILETYPE_PEM) != 1) {
    LOG_ERROR("Failed to load private key: " + std::to_string(ERR_get_error()));
    return false;
  }

  if (SSL_CTX_check_private_key(ctx.get()) != 1) {
    LOG_ERROR("Private key verification failed: " + std::to_string(ERR_get_error()));
    return false;
  }

  return true;
}

} // namespace server
