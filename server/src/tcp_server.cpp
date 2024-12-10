#include "include/tcp_server.h"

#include "include/acceptor.h"
#include "include/event_loop.h"
#include "include/event_loop_thread_pool.h"
#include "include/tcp_connection.h"

#include <array>
#include <cassert>
#include <cstdio>
#include <memory>
#include <string>

namespace server {

TcpServer::TcpServer(
    EventLoop *loop,
    const InetAddress &listenAddr,
    std::string nameArg,
    Option option
)
    : loop_(loop)
    , name_(std::move(nameArg))
    , ipPort_(listenAddr.getIpPort())
    , acceptor_(std::make_unique<Acceptor>(loop, listenAddr))
    , threadPool_(std::make_unique<EventLoopThreadPool>(loop, name_))
    , started_(false)
    , nextConnId_(1) {
  acceptor_->setConnectionHandler([this](int sockfd, const InetAddress &addr) {
    newConnection(sockfd, addr);
  });

  if (option == Option::kReusePort) {
    acceptor_->enablePortReuse();
  }
}

TcpServer::~TcpServer() {
  loop_->assertInLoopThread();

  for (const auto &[name, conn] : connections_) {
    TcpConnectionPtr connection(conn);
    connections_.erase(name);
    connection->getLoop()->runInLoop([connection] { connection->connectDestroyed(); });
  }
}

void TcpServer::start() {
  if (!started_) {
    started_ = true;
    threadPool_->start(threadInitCallback_);

    loop_->runInLoop([this]() { acceptor_->startListen(); });
  }
}

void TcpServer::newConnection(int sockfd, const InetAddress &peerAddr) {
  loop_->assertInLoopThread();

  EventLoop *ioLoop = threadPool_->getNextLoop();

  constexpr int kBufferSize = 64;

  std::array<char, kBufferSize> buf;
  snprintf(buf.data(), buf.size(), "-%s#%d", ipPort_.c_str(), nextConnId_);
  ++nextConnId_;

  std::string connName = name_ + buf.data();

  TcpConnectionPtr conn = std::make_shared<TcpConnection>(
      ioLoop,
      connName,
      std::make_unique<Socket>(sockfd),
      acceptor_->getLocalAddress(),
      peerAddr
  );

  conn->setConnectionCallback(connectionCallback_);
  conn->setMessageCallback(messageCallback_);
  conn->setWriteCompleteCallback(writeCompleteCallback_);
  conn->setCloseCallback([this](auto &&PH1) { removeConnection(std::forward<decltype(PH1)>(PH1)); }
  );

  connections_[connName] = conn;
  ioLoop->runInLoop([conn] { conn->connectEstablished(); });
}

void TcpServer::setThreadNum(int numThreads) {
  assert(!started_);
  threadPool_->setThreadNum(numThreads);
}

void TcpServer::removeConnection(const TcpConnectionPtr &conn) {
  loop_->runInLoop([this, conn]() { removeConnectionInLoop(conn); });
}

void TcpServer::removeConnectionInLoop(const TcpConnectionPtr &conn) {
  loop_->assertInLoopThread();
  size_t result = connections_.erase(conn->name());
  assert(result == 1);
  EventLoop *ioLoop = conn->getLoop();
  ioLoop->queueInLoop([conn]() { conn->connectDestroyed(); });
}

} // namespace server