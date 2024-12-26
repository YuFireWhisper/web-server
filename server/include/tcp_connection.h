#pragma once

#include "buffer.h"
#include "channel.h"
#include "event_loop.h"
#include "inet_address.h"
#include "socket.h"
#include "types.h"

#include <any>
#include <cstdint>
#include <functional>
#include <memory>

namespace server {

class TcpConnection;

using TcpConnectionPtr = std::shared_ptr<TcpConnection>;

class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
  using ConnectionCallback = std::function<void(const TcpConnectionPtr &)>;
  using MessageCallback = std::function<void(const TcpConnectionPtr &, Buffer *, TimeStamp)>;
  using WriteCompleteCallback = std::function<void(const TcpConnectionPtr &)>;
  using CloseCallback = std::function<void(const TcpConnectionPtr &)>;
  using HighWaterMarkCallback = std::function<void(const TcpConnectionPtr &, size_t)>;
  using ErrorCallback = std::function<void(const TcpConnectionPtr &)>;

  enum class State : int8_t { kDisconnected, kConnecting, kConnected, kDisconnecting };

  TcpConnection(
      EventLoop *loop,
      std::string name,
      std::unique_ptr<Socket> socket,
      const InetAddress &localAddr,
      const InetAddress &peerAddr
  );

  ~TcpConnection();

  TcpConnection(const TcpConnection &) = delete;
  TcpConnection &operator=(const TcpConnection &) = delete;

  void setContext(const std::any &context) { context_ = context; }
  void setContext(std::any &&context) { context_ = std::move(context); }
  const std::any &getContext() const { return context_; }
  std::any *getMutableContext() { return &context_; }

  EventLoop *getLoop() const { return loop_; }
  const std::string &name() const { return name_; }
  const InetAddress &localAddress() const { return localAddr_; }
  const InetAddress &peerAddress() const { return peerAddr_; }
  bool connected() const { return state_ == State::kConnected; }

  void send(const std::string &message);
  void send(std::string_view message);
  void send(Buffer *buffer);

  void shutdown();
  void forceClose();

  void setConnectionCallback(const ConnectionCallback &cb) { connectionCallback_ = cb; }
  void setMessageCallback(const MessageCallback &cb) { messageCallback_ = cb; }
  void setWriteCompleteCallback(const WriteCompleteCallback &cb) { writeCompleteCallback_ = cb; }
  void setCloseCallback(const CloseCallback &cb) { closeCallback_ = cb; }
  void setErrorCallback(const ErrorCallback &cb) { errorCallback_ = cb; }
  void setHighWaterMarkCallback(const HighWaterMarkCallback &cb, size_t highWaterMark) {
    highWaterMarkCallback_ = cb;
    highWaterMark_ = highWaterMark;
  }

  void connectEstablished();
  void connectDestroyed();

private:
  void handleRead(TimeStamp receiveTime);
  void handleWrite();
  void handleClose();
  void handleError();

  void sendInLoop(const void *message, size_t len);
  void shutdownInLoop();
  void forceCloseInLoop();

  void setState(State state) { state_ = state; }

  EventLoop *loop_;
  const std::string name_;
  State state_;

  std::unique_ptr<Socket> socket_;
  std::unique_ptr<Channel> channel_;
  const InetAddress localAddr_;
  const InetAddress peerAddr_;

  Buffer inputBuffer_;
  Buffer outputBuffer_;
  std::any context_;

  std::atomic<bool> channelRemoved_{false};
  std::atomic<bool> destroying_{false};

  ConnectionCallback connectionCallback_ = [](const TcpConnectionPtr &) {};
  MessageCallback messageCallback_ = [](const TcpConnectionPtr &, Buffer *, TimeStamp) {};
  WriteCompleteCallback writeCompleteCallback_ = [](const TcpConnectionPtr &) {};
  CloseCallback closeCallback_ = [](const TcpConnectionPtr &) {};
  HighWaterMarkCallback highWaterMarkCallback_ = [](const TcpConnectionPtr &, size_t) {};
  ErrorCallback errorCallback_ = [](const TcpConnectionPtr &) {};
  size_t highWaterMark_ = kDefaultHighWaterMark;
};

} // namespace server
