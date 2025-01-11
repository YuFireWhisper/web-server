#include "include/acceptor.h"

#include "include/channel.h"
#include "include/event_loop.h"
#include "include/inet_address.h"
#include "include/log.h"
#include "include/socket.h"
#include "include/time_stamp.h"

#include <cerrno>

#include <sys/socket.h>

namespace server {

Acceptor::Acceptor(
    EventLoop *eventLoop,
    const InetAddress &listenAddress,
    const ServerConfig &config
)
    : eventLoop_(eventLoop)
    , serverSocket_(std::make_unique<Socket>())
    , serverChannel_(std::make_unique<Channel>(eventLoop, serverSocket_->fd()))
    , isListening_(false)
    , maxAcceptsPerCall_(config.maxAcceptPerCall)
    , maxConnections_(config.maxConnections) {
  serverSocket_->enableAddressReuse();
  serverSocket_->enablePortReuse();
  serverSocket_->bindToAddress(listenAddress);

  serverChannel_->setReadCallback([this](TimeStamp) { handleConnection(); });
}

void Acceptor::startListen() {
  if (isListening()) {
    return;
  }

  serverSocket_->startListening(SOMAXCONN);
  serverChannel_->enableReading();
  isListening_ = true;
}

void Acceptor::handleConnection() {
  sockaddr_in addr;

  for (int i = 0; i < maxAcceptsPerCall_; ++i) {
    int connfd = serverSocket_->acceptConnection(addr);

    if (connfd < 0) {
      break;
    }

    if (!handleConnectionLimit()) {
      ::close(connfd);
      LOG_WARN("Max connections reached, new connection rejected");
      break;
    }

    Socket *sock = socketPool_.acquire();
    sock->attachFd(connfd);

    if (connectionHandler_) {
      connectionHandler_(connfd, InetAddress(addr));
    }
  }
}

void Acceptor::processConnection(Socket &&connection, const InetAddress &peerAddress) {
  int fd = connection.fd();
  connection.detachFd();
  if (connectionHandler_) {
    connectionHandler_(fd, peerAddress);
  }
}

bool Acceptor::handleConnectionLimit() {
  int currentConnections = connectionCount_.load();
  return currentConnections < maxConnections_;
}

void Acceptor::enablePortReuse() {
  serverSocket_->enablePortReuse();
}

InetAddress Acceptor::getLocalAddress() const {
  return serverSocket_->getLocalAddress();
}

void Acceptor::stop() {
  if (serverChannel_) {
    serverChannel_->disableAll();
    serverChannel_->remove();
  }

  isListening_ = false;
}

} // namespace server
