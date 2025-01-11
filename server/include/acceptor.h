#pragma once

#include "include/config_defaults.h"
#include "include/object_pool.h"
#include "include/resource_manager.h"
#include "include/socket.h"

#include <functional>
#include <memory>

namespace server {

class EventLoop;
class InetAddress;
class Socket;
class Channel;

class Acceptor {
public:
  using ConnectionHandler = std::function<void(int socketFd, const InetAddress &)>;

  Acceptor(
      EventLoop *eventLoop,
      const InetAddress &listenAddress,
      const ServerConfig &config = ServerConfig()
  );

  void startListen();
  void stop();

  void setConnectionHandler(const ConnectionHandler &handler) { connectionHandler_ = handler; }
  void enablePortReuse();

  [[nodiscard]] InetAddress getLocalAddress() const;
  [[nodiscard]] bool isListening() const { return isListening_; }

  void incrementConnection() { connectionCount_.fetch_add(1); }
  void decrementConnection() { connectionCount_.fetch_sub(1); }

private:
  struct AcceptorResourceLimits : ResourceLimits {
    AcceptorResourceLimits() {
      maxEvents      = 1;
      maxRequests    = 1;
      maxConnections = 1;
    }
  };

  void handleConnection();
  void processConnection(Socket &&connection, const InetAddress &peerAddress);
  bool handleConnectionLimit();

  EventLoop *eventLoop_;
  std::unique_ptr<Socket> serverSocket_;
  std::unique_ptr<Channel> serverChannel_;
  ConnectionHandler connectionHandler_;
  bool isListening_;
  ObjectPool<Socket, 32768> socketPool_;

  std::atomic<int> connectionCount_;
  const int maxAcceptsPerCall_;
  const int maxConnections_;
};

} // namespace server
