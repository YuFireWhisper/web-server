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

Acceptor::Acceptor(EventLoop *eventLoop, const InetAddress &listenAddress)
    : eventLoop_(eventLoop)
    , serverSocket_(std::make_unique<Socket>())
    , serverChannel_(std::make_unique<Channel>(eventLoop, serverSocket_->getSocketFd()))
    , isListening_(false) {
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
  try {
    Socket newConnection    = serverSocket_->acceptNewConnection();
    InetAddress peerAddress = newConnection.getRemoteAddress();
    processConnection(std::move(newConnection), peerAddress);
  } catch (const SocketException &error) {
    if (errno == EMFILE || errno == ENFILE) {
      handleResourceLimit(error.what());
    }
    LOG_ERROR("Accept failed: " + std::string(error.what()));
  }
}

void Acceptor::processConnection(Socket &&connection, const InetAddress &peerAddress) {
  int fd = connection.getSocketFd();
  connection.detachFd();
  if (connectionHandler_) {
    connectionHandler_(fd, peerAddress);
  }
}

void Acceptor::handleResourceLimit(const std::string &errorMessage) {
  LOG_FATAL("Resource limit reached: " + errorMessage);
  abort();
}

void Acceptor::enablePortReuse() {
  serverSocket_->enablePortReuse();
}

InetAddress Acceptor::getLocalAddress() const {
  return serverSocket_->getLocalAddress();
}

} // namespace server
