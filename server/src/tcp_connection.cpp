#include "include/tcp_connection.h"

#include <cerrno>
#include <cstring>

#include <system_error>

namespace server {
using std::memory_order_acquire;

TcpConnection::TcpConnection(
    EventLoop *loop,
    std::string name,
    std::unique_ptr<Socket> socket,
    const InetAddress &localAddr,
    const InetAddress &peerAddr
)
    : loop_(loop)
    , name_(std::move(name))
    , socket_(std::move(socket))
    , channel_(std::make_unique<Channel>(loop, socket_->fd()))
    , localAddr_(localAddr)
    , peerAddr_(peerAddr) {

  socket_->enableNonBlocking();
  socket_->enableKeepAlive();

  channel_->setReadCallback([this](TimeStamp ts) { handleRead(ts); });
  channel_->setWriteCallback([this]() { handleWrite(); });
  channel_->setCloseCallback([this]() { handleClose(); });
  channel_->setErrorCallback([this]() { handleError(); });
}

TcpConnection::~TcpConnection() {
  channel_->disableAll();
  channel_->remove();
}

void TcpConnection::send(std::string_view message) {
  if (loop_->isInLoopThread()) {
    sendInLoop(message.data(), message.size());
  } else {
    auto messageData = std::string(message);
    loop_->runInLoop([this, messageData = std::move(messageData)]() {
      sendInLoop(messageData.data(), messageData.size());
    });
  }
}

void TcpConnection::send(Buffer *buffer) {
  if (buffer == nullptr) {
    return;
  }

  auto data = buffer->readAll();
  if (loop_->isInLoopThread()) {
    sendInLoop(data.data(), data.size());
  } else {
    auto messageData = std::string(data);
    loop_->runInLoop([this, messageData = std::move(messageData)]() {
      sendInLoop(messageData.data(), messageData.size());
    });
  }
}

void TcpConnection::sendInLoop(const void *message, size_t len) {
  loop_->assertInLoopThread();

  if (state_.load(memory_order_acquire) == State::kDisconnected) {
    return;
  }

  ssize_t writtenBytes  = 0;
  size_t remainingBytes = len;
  bool errorOccurred    = false;
  size_t retryCount     = 0;

  if (!channel_->isWriting() && outputBuffer_.readableSize() == 0) {
    while (retryCount < kMaxSendRetryCount && remainingBytes > 0) {
      try {
        writtenBytes = (ssize_t)socket_->write(
            static_cast<const char *>(message) + (len - remainingBytes),
            remainingBytes
        );
        remainingBytes -= writtenBytes;

        if (remainingBytes == 0 && writeCompleteCallback_) {
          loop_->queueInLoop([this]() { writeCompleteCallback_(shared_from_this()); });
        }
      } catch (const std::system_error &e) {
        if (e.code().value() != EWOULDBLOCK) {
          errorOccurred = true;
        }
        break;
      }
      retryCount++;
    }
  }

  if (!errorOccurred && remainingBytes > 0) {
    size_t totalBytes = remainingBytes + outputBuffer_.readableSize();
    if (totalBytes >= highWaterMark_ && outputBuffer_.readableSize() < highWaterMark_
        && highWaterMarkCallback_) {
      loop_->queueInLoop([this, totalBytes]() {
        highWaterMarkCallback_(shared_from_this(), totalBytes);
      });
    }

    outputBuffer_.write(
        static_cast<const char *>(message) + (len - remainingBytes),
        remainingBytes
    );

    if (!channel_->isWriting()) {
      channel_->enableWriting();
    }
  }
}

void TcpConnection::handleWrite() {
  loop_->assertInLoopThread();

  if (state_.load(std::memory_order_acquire) == State::kSSLHandshaking) {
    continueSSLHandshake();
    return;
  }

  if (channel_->isWriting()) {
    auto data = outputBuffer_.readAll();
    try {
      auto writtenBytes = socket_->write(data.data(), data.size());
      outputBuffer_.read(writtenBytes);

      if (outputBuffer_.readableSize() == 0) {
        channel_->disableWriting();

        if (writeCompleteCallback_) {
          loop_->queueInLoop([this]() { writeCompleteCallback_(shared_from_this()); });
        }

        if (state_.load(std::memory_order_acquire) == State::kDisconnecting) {
          shutdownInLoop();
        }
      }
    } catch (const std::system_error &e) {
      if (e.code().value() != EWOULDBLOCK) {
        handleError();
      }
    }
  }
}

void TcpConnection::handleRead(TimeStamp receiveTime) {
  if (!loop_->isInLoopThread()) {
    loop_->runInLoop([this, receiveTime]() { handleRead(receiveTime); });
    return;
  }

  auto currentState = state_.load(std::memory_order_acquire);
  if (currentState == State::kDisconnected) {
    return;
  }

  if (currentState == State::kSSLHandshaking) {
    continueSSLHandshake();
    return;
  }

  try {
    auto bytesRead = socket_->read(inputBuffer_);
    if (bytesRead > 0) {
      messageCallback_(shared_from_this(), &inputBuffer_, receiveTime);
    } else {
      handleClose();
    }
  } catch (const std::system_error &e) {
    handleError();
  }
}

void TcpConnection::handleClose() {
  if (!loop_->isInLoopThread()) {
    loop_->runInLoop([this]() { handleClose(); });
    return;
  }

  auto currentState = state_.load(std::memory_order_acquire);
  if (currentState != State::kDisconnected) {
    setState(State::kDisconnected);
    channel_->disableAll();

    auto guardThis = shared_from_this();
    if (connectionCallback_) {
      connectionCallback_(guardThis);
    }

    if (closeCallback_) {
      closeCallback_(guardThis);
    }

    channel_->remove();
  }
}

void TcpConnection::handleError() {
  int errorCode      = 0;
  socklen_t errorLen = sizeof(errorCode);

  if (::getsockopt(channel_->fd(), SOL_SOCKET, SO_ERROR, &errorCode, &errorLen) == 0
      && errorCode != 0) {

    if (errorCallback_) {
      errorCallback_(shared_from_this());
    }

    if (errorCode == ECONNRESET || errorCode == ETIMEDOUT || errorCode == EPIPE) {
      handleClose();
    }
  }
}

void TcpConnection::shutdown() {
  auto expectedState = State::kConnected;
  if (state_.compare_exchange_strong(expectedState, State::kDisconnecting)) {
    loop_->runInLoop([this]() { shutdownInLoop(); });
  }
}

void TcpConnection::shutdownInLoop() {
  loop_->assertInLoopThread();

  if (!channel_->isWriting()) {
    socket_->closeWriteEnd();
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
    loop_->runInLoop([this]() { forceCloseInLoop(); });
  }
}

void TcpConnection::forceCloseInLoop() {
  loop_->assertInLoopThread();

  auto currentState = state_.load(std::memory_order_acquire);
  if (currentState == State::kConnected || currentState == State::kDisconnecting) {
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

void TcpConnection::enableSSL(const std::string &certFile, const std::string &keyFile) {
  loop_->assertInLoopThread();

  if (!socket_) {
    return;
  }
  socket_->initSSL(certFile, keyFile);
}

void TcpConnection::startSSLHandshake(bool isServer) {
  loop_->assertInLoopThread();

  if (!socket_ || !socket_->isSSLEnabled()) {
    return;
  }

  isServer_.store(isServer, std::memory_order_release);
  setState(State::kSSLHandshaking);
  sslHandshakeComplete_.store(false, std::memory_order_release);

  channel_->enableReading();
  loop_->queueInLoop([this]() { handleSSLHandshake(); });
}

void TcpConnection::handleSSLHandshake() {
  loop_->assertInLoopThread();

  if (!socket_ || (socket_->getSSL() == nullptr)) {
    return;
  }

  int result = SSL_accept(socket_->getSSL());
  if (result <= 0) {
    int sslError = SSL_get_error(socket_->getSSL(), result);
    switch (sslError) {
      case SSL_ERROR_WANT_READ:
        channel_->enableReading();
        channel_->disableWriting();
        return;

      case SSL_ERROR_WANT_WRITE:
        channel_->enableWriting();
        channel_->enableReading();
        return;

      case SSL_ERROR_SYSCALL:
        if (result == 0) {
          handleClose();
          return;
        }
        if (errno != 0) {
          handleError();
        }
        handleClose();
        return;

      case SSL_ERROR_SSL:
      case SSL_ERROR_ZERO_RETURN:
      default:
        handleClose();
        return;
    }
  }

  setState(State::kConnected);
  sslHandshakeComplete_.store(true, std::memory_order_release);
  channel_->enableReading();

  if (connectionCallback_) {
    connectionCallback_(shared_from_this());
  }
}

void TcpConnection::continueSSLHandshake() {
  loop_->assertInLoopThread();

  if (state_.load(std::memory_order_acquire) != State::kSSLHandshaking) {
    return;
  }
  handleSSLHandshake();
}

bool TcpConnection::processSSLHandshakeResult(int result) {
  if (result == 1) {
    return true;
  }

  if (!socket_ || (socket_->getSSL() == nullptr)) {
    return false;
  }

  int sslError = SSL_get_error(socket_->getSSL(), result);
  switch (sslError) {
    case SSL_ERROR_WANT_READ:
      channel_->enableReading();
      channel_->disableWriting();
      return false;

    case SSL_ERROR_WANT_WRITE:
      channel_->enableWriting();
      channel_->enableReading();
      return false;

    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    default:
      handleClose();
      return false;
  }
}

void TcpConnection::connectEstablished() {
  loop_->assertInLoopThread();

  setState(State::kConnected);
  channel_->enableReading();

  if (connectionCallback_) {
    connectionCallback_(shared_from_this());
  }
}

void TcpConnection::connectDestroyed() {
  loop_->assertInLoopThread();

  auto currentState = state_.load(std::memory_order_acquire);
  if (currentState == State::kConnected) {
    setState(State::kDisconnected);
    channel_->disableAll();

    if (connectionCallback_) {
      connectionCallback_(shared_from_this());
    }
  }

  channel_->remove();
}

} // namespace server
