#include "include/tcp_connection.h"

#include "include/event_loop.h"
#include "include/log.h"
#include "include/poller.h"

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
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
  socket_->enableNonBlocking();
  socket_->enableKeepAlive();

  channel_->setReadCallback([this](auto &&PH1) { handleRead(std::forward<decltype(PH1)>(PH1)); });
  channel_->setWriteCallback([this] { handleWrite(); });
  channel_->setCloseCallback([this] { handleClose(); });
  channel_->setErrorCallback([this] { handleError(); });
}

TcpConnection::~TcpConnection() {
  channel_->disableAll();
  channel_->remove();

  if (socket_->hasActiveConnection()) {
    LOG_WARN("Connect did not close properly!");
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

  if (loop_->isInLoopThread()) {
    sendInLoop(buffer->peek(), buffer->readableBytes());
    buffer->retrieveAll();
  } else {
    std::string message(buffer->peek(), buffer->readableBytes());
    loop_->runInLoop([this, message]() { sendInLoop(message.data(), message.size()); });
    buffer->retrieveAll();
  }
}

void TcpConnection::sendInLoop(const void *message, size_t len) {
  loop_->assertInLoopThread();
  if (len >= highWaterMark_ && highWaterMarkCallback_) {
    loop_->queueInLoop([this, len]() { highWaterMarkCallback_(shared_from_this(), len); });
  }

  ssize_t nwrote   = 0;
  size_t remaining = len;
  bool faultError  = false;

  if (!channel_->isWriting() && outputBuffer_.readableBytes() == 0) {
    nwrote = ::write(channel_->fd(), message, len);

    if (nwrote >= 0) {
      remaining = len - nwrote;

      if (remaining == 0 && writeCompleteCallback_) {
        loop_->queueInLoop([this]() { writeCompleteCallback_(shared_from_this()); });
      }
    } else {
      if (errno != EWOULDBLOCK) {
        if (errno == EPIPE || errno == ECONNRESET) {
          faultError = true;
        }
      }
    }
  }

  if (!faultError && remaining > 0) {
    outputBuffer_.append(static_cast<const char *>(message) + nwrote, remaining);

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
    ssize_t result = ::write(channel_->fd(), outputBuffer_.peek(), outputBuffer_.readableBytes());

    if (result > 0) {
      outputBuffer_.retrieve(result);
      if (outputBuffer_.readableBytes() == 0) {
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
  loop_->assertInLoopThread();

  if (state_ != State::kDisconnected) {
    setState(State::kDisconnected);

    channel_->disableAll();

    if (connectionCallback_) {
      connectionCallback_(shared_from_this());
    }

    if (channel_) {
      channel_->remove();
    }

    if (closeCallback_) {
      closeCallback_(shared_from_this());
    }
  }
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
  int savedErrno = 0;
  ssize_t result = inputBuffer_.readData(socket_->getSocketFd(), &savedErrno);

  if (result > 0) {
    messageCallback_(shared_from_this(), &inputBuffer_, receiveTime);
  } else if (result == 0) {
    handleClose();
  } else {
    errno = savedErrno;
    LOG_ERROR("Read Error" + std::string(strerror(errno)));
    handleError();
  }
}

void TcpConnection::connectEstablished() {
  loop_->assertInLoopThread();

  assert(state_ == State::kConnecting);
  setState(State::kConnected);

  channel_->enableReading();

  channel_->setReadCallback([this](auto &&PH1) { handleRead(std::forward<decltype(PH1)>(PH1)); });
  channel_->setWriteCallback([this] { handleWrite(); });
  channel_->setCloseCallback([this] { handleClose(); });
  channel_->setErrorCallback([this] { handleError(); });

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
