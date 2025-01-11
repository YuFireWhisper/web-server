#pragma once

#include "include/buffer.h"
#include "include/channel.h"
#include "include/event_loop.h"
#include "include/inet_address.h"
#include "include/socket.h"
#include "include/types.h"

#include <any>
#include <atomic>
#include <memory>
#include <string>

namespace server {

class TcpConnection;
using TcpConnectionPtr = std::shared_ptr<TcpConnection>;

class TcpConnection final : public std::enable_shared_from_this<TcpConnection> {
public:
  using ConnectionCallback = std::function<void(const TcpConnectionPtr&)>;
  using MessageCallback = std::function<void(const TcpConnectionPtr&, Buffer*, TimeStamp)>;
  using WriteCompleteCallback = std::function<void(const TcpConnectionPtr&)>;
  using CloseCallback = std::function<void(const TcpConnectionPtr&)>;
  using HighWaterMarkCallback = std::function<void(const TcpConnectionPtr&, size_t)>;
  using ErrorCallback = std::function<void(const TcpConnectionPtr&)>;

  enum class State : int8_t {
    kDisconnected,
    kConnecting,
    kConnected, 
    kDisconnecting,
    kSSLHandshaking
  };

  TcpConnection(EventLoop* loop, 
                std::string name,
                std::unique_ptr<Socket> socket,
                const InetAddress& localAddr,  
                const InetAddress& peerAddr);

  ~TcpConnection();

  TcpConnection(const TcpConnection&) = delete;
  TcpConnection& operator=(const TcpConnection&) = delete;

  void setContext(const std::any& context) { context_ = context; }
  void setContext(std::any&& context) { context_ = std::move(context); }
  const std::any& getContext() const noexcept { return context_; }
  std::any* getMutableContext() noexcept { return &context_; }

  [[nodiscard]] EventLoop* getLoop() const noexcept { return loop_; }
  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  [[nodiscard]] const InetAddress& localAddress() const noexcept { return localAddr_; }
  [[nodiscard]] const InetAddress& peerAddress() const noexcept { return peerAddr_; }
  [[nodiscard]] bool connected() const noexcept { return state_.load() == State::kConnected; }
  [[nodiscard]] bool isSSLEnabled() const noexcept { return socket_ && socket_->isSSLEnabled(); }
  [[nodiscard]] bool isSSLConnected() const noexcept { return socket_ && socket_->isSSLConnected(); }

  void send(std::string_view message);
  void send(Buffer* buffer);
  void shutdown();
  void forceClose();

  void setConnectionCallback(ConnectionCallback cb) noexcept { connectionCallback_ = std::move(cb); }
  void setMessageCallback(MessageCallback cb) noexcept { messageCallback_ = std::move(cb); }
  void setWriteCompleteCallback(WriteCompleteCallback cb) noexcept { writeCompleteCallback_ = std::move(cb); }
  void setCloseCallback(CloseCallback cb) noexcept { closeCallback_ = std::move(cb); }
  void setErrorCallback(ErrorCallback cb) noexcept { errorCallback_ = std::move(cb); }
  void setHighWaterMarkCallback(HighWaterMarkCallback cb, size_t highWaterMark) noexcept {
    highWaterMarkCallback_ = std::move(cb);
    highWaterMark_ = highWaterMark;
  }

  void connectEstablished();
  void connectDestroyed();
  void enableSSL(const std::string& certFile, const std::string& keyFile);
  void startSSLHandshake(bool isServer);

private:
  void handleRead(TimeStamp receiveTime);
  void handleWrite();
  void handleClose();
  void handleError();
  
  void sendInLoop(const void* message, size_t len);
  void shutdownInLoop();
  void forceCloseInLoop();
  
  void handleSSLHandshake();
  void continueSSLHandshake();
  bool processSSLHandshakeResult(int result);

  void setState(State state) noexcept {
    state_.store(state, std::memory_order_release);
  }

  EventLoop* const loop_;
  const std::string name_;
  std::atomic<State> state_{ State::kConnecting };
  
  std::unique_ptr<Socket> socket_;
  std::unique_ptr<Channel> channel_;
  const InetAddress localAddr_;
  const InetAddress peerAddr_;

  Buffer inputBuffer_;
  Buffer outputBuffer_;
  std::any context_;
  
  std::atomic<bool> isServer_{ false };
  std::atomic<bool> sslHandshakeComplete_{ false };
  
  ConnectionCallback connectionCallback_;
  MessageCallback messageCallback_;
  WriteCompleteCallback writeCompleteCallback_;
  CloseCallback closeCallback_;
  HighWaterMarkCallback highWaterMarkCallback_;
  ErrorCallback errorCallback_;
  
  size_t highWaterMark_{ kDefaultHighWaterMark };
  
  static constexpr size_t kMaxSendRetryCount = 3;
};

} // namespace server
