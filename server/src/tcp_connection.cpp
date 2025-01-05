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

  LOG_DEBUG("Creating TcpConnection " + name_);
  socket_->enableNonBlocking();
  socket_->enableKeepAlive();

  LOG_DEBUG("Setting up callbacks for " + name_);
  channel_->setReadCallback([this](TimeStamp ts) {
    LOG_DEBUG("準備執行 TcpConnection " + name_ + " 的 handleRead");
    handleRead(ts);
    LOG_DEBUG("完成執行 TcpConnection " + name_ + " 的 handleRead");
  });
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

  try {
    int ret;
    if (isServer_) {
      ret = SSL_accept(socket_->getSSL());
    } else {
      ret = SSL_connect(socket_->getSSL());
    }

    if (ret <= 0) {
      int err = SSL_get_error(socket_->getSSL(), ret);
      if (err == SSL_ERROR_WANT_READ) {
        channel_->enableReading();
        channel_->disableWriting();
        return;
      }
      if (err == SSL_ERROR_WANT_WRITE) {
        channel_->enableWriting();
        channel_->disableReading();
        return;
      }
      throw SocketException("SSL handshake", ERR_get_error());
    }

    sslHandshakeComplete_ = true;
    state_                = State::kConnected;

    channel_->enableReading();
    channel_->disableWriting();

    if (connectionCallback_) {
      connectionCallback_(shared_from_this());
    }
  } catch (const SocketException &e) {
    LOG_ERROR("SSL handshake failed: " + std::string(e.what()));
    handleError();
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

void TcpConnection::handleClose() {
  LOG_DEBUG("開始關閉連接：" + name_ + ", fd=" + std::to_string(socket_->getSocketFd()));
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
}

void TcpConnection::handleError() {
  int err          = 0;
  socklen_t errlen = sizeof(err);

  if (::getsockopt(channel_->fd(), SOL_SOCKET, SO_ERROR, &err, &errlen) == 0) {
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

void TcpConnection::handleRead(TimeStamp receiveTime) {
  loop_->assertInLoopThread();

  if (state_ == State::kDisconnected) {
    return;
  }

  if (state_ == State::kSSLHandshaking) {
    handleSSLHandshake();
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

void TcpConnection::connectEstablished() {
  LOG_DEBUG("Entering connectEstablished for " + name_);
  loop_->assertInLoopThread();
  assert(state_ == State::kConnecting);
  setState(State::kConnected);

  LOG_DEBUG("TcpConnection " + name_ + " 設置為已連接狀態");
  channel_->enableReading();
  LOG_DEBUG("TcpConnection " + name_ + " 啟用讀取");

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
