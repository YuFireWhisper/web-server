#pragma once

#include "include/config_defaults.h"
#include "include/inet_address.h"
#include "include/socket.h"

#include <chrono>
#include <functional>
#include <memory>
#include <queue>

namespace server {

class EventLoop;
class Channel;

struct PendingConnection {
  std::unique_ptr<Socket> socket;
  InetAddress peerAddress;
  std::chrono::steady_clock::time_point timestamp;

  PendingConnection(std::unique_ptr<Socket> s, const InetAddress &addr)
      : socket(std::move(s))
      , peerAddress(addr)
      , timestamp(std::chrono::steady_clock::now()) {}
};

class Acceptor {
public:
  using ConnectionHandler = std::function<void(int socketFd, const InetAddress &)>;

  Acceptor(EventLoop *eventLoop, const InetAddress &listenAddress);

  void setConnectionHandler(const ConnectionHandler &handler) { connectionHandler_ = handler; }

  [[nodiscard]] bool isListening() const { return isListening_; }
  void startListen();

  void enablePortReuse();

  [[nodiscard]] InetAddress getLocalAddress() const;

  void onResourceAvailable();
  void incrementConnectionCount() { ++numActiveConnections_; }
  void decrementConnectionCount() { --numActiveConnections_; }
  [[nodiscard]] size_t getConnectionCount() const { return numActiveConnections_; }

private:
  void handleConnection();
  void processConnection(Socket &&connection, const InetAddress &peerAddress);
  void handleResourceLimit(const std::string &errorMessage);
  [[nodiscard]] bool hasAvailableResources() const { return connectionHandler_ && !reachLimit_; }

  void cleanupTimedOutConnections();
  [[nodiscard]] bool isConnectionTimedOut(const PendingConnection &conn) const;

  EventLoop *eventLoop_;
  std::unique_ptr<Socket> serverSocket_;
  std::unique_ptr<Channel> serverChannel_;
  ConnectionHandler connectionHandler_;
  bool isListening_;

  std::atomic<size_t> numActiveConnections_{ 0 };
  std::queue<PendingConnection> pendingConnections_;
  std::mutex queueMutex_;
  bool reachLimit_{ false };
  ServerConfig config_;
};

} // namespace server
