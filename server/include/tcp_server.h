#pragma once

#include "include/tcp_connection.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace server {
class Acceptor;
class EventLoop;
class InetAddress;
class EventLoopThreadPool;

class TcpServer {
public:
  using ThreadInitCallback = std::function<void(EventLoop *)>;

  enum class Option : int8_t { kNoReusePort, kReusePort };

  TcpServer(
      EventLoop *loop,
      const InetAddress &listenAddr,
      std::string nameArg,
      bool reusePort = false
  );

  ~TcpServer();

  TcpServer(const TcpServer &)            = delete;
  TcpServer &operator=(const TcpServer &) = delete;

  void setThreadNum(int numThreads);

  void start();

  void setConnectionCallback(const TcpConnection::ConnectionCallback &cb) {
    connectionCallback_ = cb;
  }

  void setMessageCallback(const TcpConnection::MessageCallback &cb) { messageCallback_ = cb; }

  void setWriteCompleteCallback(const TcpConnection::WriteCompleteCallback &cb) {
    writeCompleteCallback_ = cb;
  }

  void setThreadInitCallback(const ThreadInitCallback &cb) { threadInitCallback_ = cb; }

  const std::string &getName() const { return name_; }
  const std::string &getIpPort() const { return ipPort_; }
  EventLoop *getLoop() const { return loop_; }

  size_t numConnections() const { return connections_.size(); }

private:
  void newConnection(int sockfd, const InetAddress &peerAddr);
  void removeConnection(const TcpConnectionPtr &conn);
  void removeConnectionInLoop(const TcpConnectionPtr &conn);
  void updateConnectionCount(bool increment);

  using ConnectionMap = std::unordered_map<std::string, TcpConnectionPtr>;

  EventLoop *loop_;
  const std::string name_;
  const std::string ipPort_;
  std::unique_ptr<Acceptor> acceptor_;
  std::unique_ptr<EventLoopThreadPool> threadPool_;

  TcpConnection::ConnectionCallback connectionCallback_;
  TcpConnection::MessageCallback messageCallback_;
  TcpConnection::WriteCompleteCallback writeCompleteCallback_;
  ThreadInitCallback threadInitCallback_;

  std::atomic<bool> started_;
  int nextConnId_;
  ConnectionMap connections_;
};

} // namespace server
