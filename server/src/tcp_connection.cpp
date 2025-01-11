#include "include/tcp_connection.h"

#include "include/event_loop.h"
#include "include/log.h"
#include "include/poller.h"

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
#include <openssl/err.h>
#include <string_view>
#include <unistd.h>

#include <sys/types.h>
namespace server {
using std::bind;

TcpConnection::TcpConnection(
    EventLoop *loop,
    std::string name,
    std::unique_ptr<Socket> socket,
    const InetAddress &localAddr,
    const InetAddress &peerAddr
)
    : loop_(loop)
    , name_(std::move(name))
    , state_(State::kConnecting)
    , socket_(std::move(socket))
    , channel_(std::make_unique<Channel>(loop, socket_->getSocketFd()))
    , localAddr_(localAddr)
    , peerAddr_(peerAddr) {

  LOG_DEBUG("Creating TcpConnection " + name_ + ", thread ID: " + std::to_string(pthread_self()));
  socket_->enableNonBlocking();
  socket_->enableKeepAlive();

  LOG_DEBUG("Setting up callbacks for " + name_);
  channel_->setReadCallback([this](TimeStamp ts) { handleRead(ts); });
  channel_->setWriteCallback([this] { handleWrite(); });
  channel_->setCloseCallback([this] { handleClose(); });
  channel_->setErrorCallback([this] { handleError(); });
  LOG_DEBUG("Callbacks setup completed for " + name_);
}

TcpConnection::~TcpConnection() {
  channel_->disableAll();
  channel_->remove();

  if (socket_->hasActiveConnection()) {
    LOG_WARN("Connect did not close properly!");
  }
}

void TcpConnection::enableSSL(const std::string &certFile, const std::string &keyFile) {
  loop_->assertInLoopThread();
  if (!socket_) {
    return;
  }
  socket_->initializeSSL(certFile, keyFile);
}

void TcpConnection::startSSLHandshake(bool isServer) {
  loop_->assertInLoopThread();
  if (!socket_ || !socket_->isSSLEnabled()) {
    LOG_ERROR("SSL not properly initialized for connection " + name_);
    return;
  }

  LOG_INFO(
      "Starting SSL handshake for connection " + name_ + (isServer ? " (server)" : " (client)")
  );
  isServer_             = isServer;
  state_                = State::kSSLHandshaking;
  sslHandshakeComplete_ = false;

  channel_->enableReading();

  loop_->queueInLoop([this] { handleSSLHandshake(); });
}

void TcpConnection::handleSSLHandshake() {
  loop_->assertInLoopThread();
  LOG_DEBUG("Entering handleSSLHandshake for " + name_);

  int ret = SSL_accept(socket_->getSSL());
  LOG_DEBUG("SSL_accept returned " + std::to_string(ret));

  if (ret <= 0) {
    int err = SSL_get_error(socket_->getSSL(), ret);
    LOG_DEBUG("SSL_get_error returned " + std::to_string(err));

    switch (err) {
      case SSL_ERROR_WANT_READ:
        LOG_DEBUG(name_ + " SSL handshake needs more data (want read)");
        channel_->enableReading();
        return;

      case SSL_ERROR_WANT_WRITE:
        LOG_DEBUG(name_ + " SSL handshake needs to write");
        channel_->enableWriting();
        return;

      case SSL_ERROR_SYSCALL:
        if (ret == 0) {
          LOG_ERROR(name_ + " SSL handshake failed: EOF in violation of protocol");
          handleClose();
          return;
        }
        if (errno != 0) {
          LOG_ERROR(name_ + " SSL handshake syscall error: " + std::string(strerror(errno)));
        }
        handleClose();
        return;

      case SSL_ERROR_SSL: {
        unsigned long e = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(e, err_buf, sizeof(err_buf));
        LOG_ERROR(name_ + " SSL handshake protocol error: " + std::string(err_buf));
        handleClose();
        return;
      }

      case SSL_ERROR_ZERO_RETURN:
        LOG_ERROR(name_ + " SSL handshake failed: connection closed by peer");
        handleClose();
        return;

      default:
        LOG_ERROR(name_ + " SSL handshake failed with unknown error: " + std::to_string(err));
        handleClose();
        return;
    }
  }

  LOG_INFO("SSL handshake completed successfully for " + name_);
  setState(State::kConnected);
  sslHandshakeComplete_ = true;

  channel_->enableReading();

  if (connectionCallback_) {
    connectionCallback_(shared_from_this());
  }
}

void TcpConnection::continueSSLHandshake() {
  loop_->assertInLoopThread();
  if (state_ != State::kSSLHandshaking) {
    return;
  }

  handleSSLHandshake();
}

bool TcpConnection::processSSLHandshakeResult(int result) {
  if (result == 1) {
    return true; // Handshake completed successfully
  }

  int err = SSL_get_error(socket_->getSSL(), result);
  switch (err) {
    case SSL_ERROR_WANT_READ:
      LOG_DEBUG(name_ + " SSL handshake needs more data (want read)");
      channel_->enableReading();
      channel_->disableWriting();
      return false;

    case SSL_ERROR_WANT_WRITE:
      LOG_DEBUG(name_ + " SSL handshake needs to write");
      channel_->enableWriting();
      channel_->enableReading();
      return false;

    case SSL_ERROR_ZERO_RETURN:
      LOG_ERROR(name_ + " SSL handshake failed: connection closed by peer");
      handleClose();
      return false;

    case SSL_ERROR_SYSCALL:
      if (result == 0) {
        LOG_ERROR(name_ + " SSL handshake failed: EOF in violation of protocol");
      } else if (errno != 0) {
        LOG_ERROR(name_ + " SSL handshake syscall error: " + std::string(strerror(errno)));
      }
      handleClose();
      return false;

    case SSL_ERROR_SSL: {
      unsigned long e = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(e, err_buf, sizeof(err_buf));
      LOG_ERROR(name_ + " SSL handshake protocol error: " + std::string(err_buf));
      handleClose();
      return false;
    }

    default:
      LOG_ERROR(name_ + " SSL handshake failed with unknown error: " + std::to_string(err));
      handleClose();
      return false;
  }
}

void TcpConnection::send(const std::string &message) {
  if (loop_->isInLoopThread()) {
    sendInLoop(message.data(), message.size());
  } else {
    loop_->runInLoop([this, message]() { sendInLoop(message.data(), message.size()); });
  }
}

void TcpConnection::send(std::string_view message) {
  sendInLoop(message.data(), message.size());
}

void TcpConnection::send(Buffer *buffer) {
  if (buffer == nullptr) {
    LOG_ERROR("Attempting to send null buffer");
    return;
  }

  auto context = buffer->readAll();

  if (loop_->isInLoopThread()) {
    sendInLoop(context.data(), context.size());
  } else {
    std::string message(context);
    loop_->runInLoop([this, message]() { sendInLoop(message.data(), message.size()); });
  }
}

void TcpConnection::sendInLoop(const void *message, size_t len) {
  loop_->assertInLoopThread();

  if (state_ == State::kDisconnected) {
    LOG_WARN("Disconnected, give up writing");
    return;
  }

  ssize_t nwrote   = 0;
  size_t remaining = len;
  bool faultError  = false;

  if (!channel_->isWriting() && outputBuffer_.readableSize() == 0) {
    try {
      nwrote    = static_cast<ssize_t>(socket_->writeData(message, len));
      remaining = len - nwrote;

      if (remaining == 0 && writeCompleteCallback_) {
        loop_->queueInLoop([this] { writeCompleteCallback_(shared_from_this()); });
      }
    } catch (const SocketException &e) {
      nwrote = 0;
      LOG_ERROR("Write error: " + std::string(e.what()));
      if (errno != EWOULDBLOCK) {
        if (errno == EPIPE || errno == ECONNRESET) {
          faultError = true;
        }
      }
    }
  }

  if (!faultError && remaining > 0) {
    if (remaining + outputBuffer_.readableSize() >= highWaterMark_
        && outputBuffer_.readableSize() < highWaterMark_ && highWaterMarkCallback_) {
      loop_->queueInLoop([this, remaining] {
        highWaterMarkCallback_(shared_from_this(), remaining + outputBuffer_.readableSize());
      });
    }
    outputBuffer_.write(static_cast<const char *>(message) + nwrote, remaining);
    if (!channel_->isWriting()) {
      channel_->enableWriting();
    }
  }
}
void TcpConnection::shutdown() {
  if (state_ == State::kConnected) {
    setState(State::kDisconnecting);
    loop_->runInLoop([capture0 = shared_from_this()] { capture0->shutdownInLoop(); });
  }
}

void TcpConnection::shutdownInLoop() {
  loop_->assertInLoopThread();

  if (!channel_->isWriting()) {
    socket_->closeWriteEnd();

    channel_->disableAll();

    setState(State::kDisconnected);

    if (closeCallback_) {
      closeCallback_(shared_from_this());
    }

    channel_->remove();
  }
}

void TcpConnection::forceClose() {
  if (loop_->isInLoopThread()) {
    forceCloseInLoop();
  } else {
    loop_->runInLoop([capture0 = shared_from_this()] { capture0->forceCloseInLoop(); });
  }
}

void TcpConnection::forceCloseInLoop() {
  loop_->assertInLoopThread();

  if (state_ == State::kConnected || state_ == State::kDisconnecting) {
    setState(State::kDisconnected);

    channel_->disableAll();

    if (connectionCallback_) {
      connectionCallback_(shared_from_this());
    }

    socket_->closeWriteEnd();

    if (closeCallback_) {
      closeCallback_(shared_from_this());
    }
    channel_->remove();
  }
}

void TcpConnection::handleWrite() {
  loop_->assertInLoopThread();

  if (state_ == State::kSSLHandshaking) {
    continueSSLHandshake();
    return;
  }

  if (channel_->isWriting()) {
    auto context   = outputBuffer_.preview(outputBuffer_.readableSize());
    ssize_t result = ::write(channel_->fd(), context.data(), outputBuffer_.readableSize());

    if (result > 0) {
      outputBuffer_.read(result);
      if (outputBuffer_.readableSize() == 0) {
        channel_->disableWriting();

        if (writeCompleteCallback_) {
          loop_->queueInLoop([this]() { writeCompleteCallback_(shared_from_this()); });
        }

        if (state_ == State::kDisconnecting) {
          shutdownInLoop();
        }
      }
    }
  }
}

void TcpConnection::handleRead(TimeStamp receiveTime) {
  if (!loop_->isInLoopThread()) {
    loop_->runInLoop([guardThis = shared_from_this(), receiveTime] { guardThis->handleRead(receiveTime); });
    return;
  }

  loop_->assertInLoopThread();

  if (state_ == State::kDisconnected) {
    return;
  }

  if (state_ == State::kSSLHandshaking) {
    LOG_DEBUG(name_ + " Received data during SSL handshake");
    continueSSLHandshake();
    return;
  }

  auto guardThis = shared_from_this();

  try {
    auto n = static_cast<ssize_t>(socket_->readData(inputBuffer_));
    if (n > 0) {
      messageCallback_(guardThis, &inputBuffer_, receiveTime);
    } else if (n == 0) {
      loop_->queueInLoop([guardThis] { guardThis->handleClose(); });
    }
  } catch (const SocketException &e) {
    LOG_ERROR("Read error: " + std::string(e.what()));
    handleError();
  }
}

void TcpConnection::handleClose() {
  try {
    LOG_DEBUG(
        "開始關閉連接：" + name_ + ", fd=" + std::to_string(socket_->getSocketFd())
        + ", current thread id: " + std::to_string(pthread_self())
        + ", loop thread id: " + std::to_string(loop_->getThreadId())
    );

    if (!loop_->isInLoopThread()) {
      loop_->runInLoop([guardThis = shared_from_this()] { guardThis->handleClose(); });
      return;
    }

    loop_->assertInLoopThread();

    if (state_ != State::kDisconnected) {
      setState(State::kDisconnected);
      channel_->disableAll();

      auto guardThis = shared_from_this();

      if (connectionCallback_) {
        connectionCallback_(guardThis);
      }

      if (channel_) {
        channel_->remove();
      }

      if (closeCallback_) {
        loop_->queueInLoop([guardThis, cb = closeCallback_]() { cb(guardThis); });
      }
    }

    LOG_DEBUG("完成關閉連接：" + name_);
  } catch (const std::exception &e) {
    LOG_ERROR("handleClose error: " + std::string(e.what()));
    throw e;
  }
}

void TcpConnection::handleError() {
  int err          = 0;
  socklen_t errlen = sizeof(err);

  if (::getsockopt(channel_->fd(), SOL_SOCKET, SO_ERROR, &err, &errlen) == 0) {
    if (err == 0) {
      return;
    }

    std::string errMsg = strerror(err);

    switch (err) {
      case ECONNRESET:
        LOG_ERROR(name_ + ": Conection reset by peer: " + errMsg);
        handleClose();
        break;

      case ETIMEDOUT:
        LOG_ERROR(name_ + ": Connection timed out: " + errMsg);
        handleClose();
        break;

      case EPIPE:
        LOG_ERROR(name_ + ": Broken pipe: " + errMsg);
        handleClose();
        break;

      default:
        LOG_ERROR(
            name_ + ": Socket error: " + errMsg + " (error code: " + std::to_string(err) + ")"
        );
        if (!socket_->hasActiveConnection()) {
          handleClose();
        }
        break;
    }

    if (errorCallback_) {
      errorCallback_(shared_from_this());
    }
  } else {
    LOG_ERROR(name_ + ": Failed to get socket error");
  }
}

void TcpConnection::connectEstablished() {
  LOG_DEBUG("Entering connectEstablished for " + name_);
  loop_->assertInLoopThread();
  assert(state_ == State::kConnecting);
  setState(State::kConnected);

  channel_->enableReading();

  if (connectionCallback_) {
    connectionCallback_(shared_from_this());
  }
}

void TcpConnection::connectDestroyed() {
  loop_->assertInLoopThread();

  if (state_ == State::kConnected) {
    setState(State::kDisconnected);
    channel_->disableAll();
    connectionCallback_(shared_from_this());
    channel_->remove();
  }
}

} // namespace server
