#include "include/acceptor.h"

#include "include/channel.h"
#include "include/config_defaults.h"
#include "include/config_manager.h"
#include "include/event_loop.h"
#include "include/inet_address.h"
#include "include/log.h"
#include "include/socket.h"
#include "include/time_stamp.h"

#include <cerrno>
#include <memory>

#include <sys/socket.h>

namespace server {

Acceptor::Acceptor(EventLoop *eventLoop, const InetAddress &listenAddress)
    : eventLoop_(eventLoop)
    , serverSocket_(std::make_unique<Socket>())
    , serverChannel_(std::make_unique<Channel>(eventLoop, serverSocket_->getSocketFd()))
    , isListening_(false)
    , config_(*static_cast<ServerConfig *>(
          ConfigManager::getInstance().getConfigByOffset(kServerOffset)
      )) {
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
  cleanupTimedOutConnections();

  try {
    Socket newConnection    = serverSocket_->acceptNewConnection();
    InetAddress peerAddress = newConnection.getRemoteAddress();

    std::lock_guard<std::mutex> lock(queueMutex_);

    if (connectionHandler_ && numActiveConnections_ < config_.maxConnections) {
      processConnection(std::move(newConnection), peerAddress);
      return;
    }

    if (pendingConnections_.size() >= config_.maxPendingConnections) {
      LOG_WARN("Pending connection queue full, rejecting new connection");
      return;
    }

    LOG_INFO(
        "Queueing new connection, current queue size: " + std::to_string(pendingConnections_.size())
    );
    pendingConnections_.emplace(std::make_unique<Socket>(std::move(newConnection)), peerAddress);
  } catch (const SocketException &error) {
    LOG_ERROR("Accept failed: " + std::string(error.what()));
  }
}

void Acceptor::cleanupTimedOutConnections() {
  std::lock_guard<std::mutex> lock(queueMutex_);

  while (!pendingConnections_.empty()) {
    if (!isConnectionTimedOut(pendingConnections_.front())) {
      break;
    }

    LOG_INFO("Removing timed out connection from queue");
    pendingConnections_.pop();
  }
}

bool Acceptor::isConnectionTimedOut(const PendingConnection &conn) const {
  auto now      = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - conn.timestamp).count();
  return duration > static_cast<int64_t>(config_.pendingTimeout);
}

void Acceptor::processConnection(Socket &&connection, const InetAddress &peerAddress) {
  int fd = connection.getSocketFd();
  connection.detachFd();
  if (connectionHandler_) {
    connectionHandler_(fd, peerAddress);
  }
}

void Acceptor::handleResourceLimit(const std::string &errorMessage) {
  LOG_WARN("Resource limit reached: " + errorMessage);
  reachLimit_ = true;

  serverChannel_->disableReading();
}

void Acceptor::enablePortReuse() {
  serverSocket_->enablePortReuse();
}

InetAddress Acceptor::getLocalAddress() const {
  return serverSocket_->getLocalAddress();
}

void Acceptor::onResourceAvailable() {
  std::lock_guard<std::mutex> lock(queueMutex_);

  while (!pendingConnections_.empty() && numActiveConnections_ < config_.maxConnections) {

    auto &pending = pendingConnections_.front();
    if (isConnectionTimedOut(pending)) {
      pendingConnections_.pop();
      continue;
    }

    int fd = pending.socket->getSocketFd();
    pending.socket->detachFd();
    if (connectionHandler_) {
      connectionHandler_(fd, pending.peerAddress);
    }

    pendingConnections_.pop();
  }
}
} // namespace server
