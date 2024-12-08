#include "include/acceptor.h"

#include "include/channel.h"
#include "include/event_loop.h"
#include "include/inet_address.h"
#include "include/log.h"
#include "include/socket.h"

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

  serverChannel_->setReadCallback(std::bind(&Acceptor::handleConnection, this));
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
    Socket newConnection = serverSocket_->acceptNewConnection();
    InetAddress peerAddress = newConnection.getRemoteAddress();
    processConnection(std::move(newConnection), peerAddress);
  } catch (const SocketException &error) {
    if (errno == EMFILE || errno == ENFILE) {
      handleResourceLimit(error.what());
    }
    Logger::log(LogLevel::ERROR, "Accept failed: " + std::string(error.what()), "acceptor.log");
  }
}

void Acceptor::processConnection(Socket &&connection, const InetAddress &peerAddress) {
  if (connectionHandler_) {
    connectionHandler_(connection.getSocketFd(), peerAddress);
  }
}

void Acceptor::handleResourceLimit(const std::string &errorMessage) {
  Logger::log(LogLevel::FATAL, "Resource limit reached: " + errorMessage, "acceptor.log");
  abort();
}

void Acceptor::enablePortReuse() {
  serverSocket_->enablePortReuse();
}

} // namespace server
