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

    static std::atomic<uint64_t> connectionCount{0};
    uint64_t connection = ++connectionCount;

    if (connection % 100 == 0) {
      LOG_INFO("Total connections accepted: " + std::to_string(connection));
    }

    processConnection(std::move(newConnection), peerAddress);

    --connectionCount;
  } catch (const SocketException &error) {
    if (errno == EMFILE || errno == ENFILE) {
      handleResourceLimit(error.what());
      return;
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
    static time_t lastWarningTime = 0;
    time_t currentTime = time(nullptr);
    
    if (currentTime - lastWarningTime >= 60) {
      LOG_WARN("Resource limit reached (dropping connection): " + errorMessage);
      lastWarningTime = currentTime;
    }
    
    static std::atomic<uint64_t> droppedConnections{0};
    uint64_t dropped = ++droppedConnections;
    
    if (dropped % 1000 == 0) {
      LOG_INFO("Total dropped connections due to resource limits: " + std::to_string(dropped));
    }
}

void Acceptor::enablePortReuse() {
  serverSocket_->enablePortReuse();
}

InetAddress Acceptor::getLocalAddress() const {
  return serverSocket_->getLocalAddress();
}

} // namespace server
