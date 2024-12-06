#pragma once

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

  Acceptor(EventLoop *eventLoop, const InetAddress &listenAddress);

  void setConnectionHandler(const ConnectionHandler &handler) { connectionHandler_ = handler; }

  bool isListening() const { return isListening_; }
  void startListen();

private:
  void handleConnection();
  void processConnection(Socket &&connection, const InetAddress &peerAddress);
  void handleResourceLimit(const std::string &errorMessage);

  EventLoop *eventLoop_;
  std::unique_ptr<Socket> serverSocket_;
  std::unique_ptr<Channel> serverChannel_;
  ConnectionHandler connectionHandler_;
  bool isListening_;
};

} // namespace server
