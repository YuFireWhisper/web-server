#include "include/event_loop.h"
#include "include/inet_address.h"
#include "include/tcp_server.h"

#include <gtest/gtest.h>

namespace server {

class TcpServerTest : public ::testing::Test {
protected:
  static constexpr uint16_t kServerPort = 8080;
  static constexpr uint16_t kClientPort = 12345;
  static constexpr const char *kServerName = "TestServer";
  static constexpr const char *kLocalhost = "127.0.0.1";
  static constexpr const char *kAnyIp = "0.0.0.0";
  static constexpr int kDefaultThreads = 4;

  void SetUp() override {
    loop_ = std::make_unique<EventLoop>();
    server_ = std::make_unique<TcpServer>(loop_.get(), InetAddress(kServerPort), kServerName);
  }

  void TearDown() override {
    server_.reset();
    loop_.reset();
  }

  std::unique_ptr<EventLoop> loop_;
  std::unique_ptr<TcpServer> server_;
};

TEST_F(TcpServerTest, InitializationSetsCorrectServerProperties) {
  EXPECT_EQ(server_->getName(), kServerName);
  EXPECT_EQ(server_->getLoop(), loop_.get());
  EXPECT_EQ(server_->numConnections(), 0);
}

TEST_F(TcpServerTest, ServerStartEnablesConnectionAcceptance) {
  server_->start();
  EXPECT_EQ(server_->numConnections(), 0);
}

TEST_F(TcpServerTest, SetThreadNumConfiguresThreadPool) {
  server_->setThreadNum(kDefaultThreads);
  server_->start();
  EXPECT_EQ(server_->numConnections(), 0);
}

TEST_F(TcpServerTest, ConnectionCallbackIsInvoked) {
  size_t connectionCount = 0;
  server_->setConnectionCallback([&connectionCount](const TcpConnectionPtr &) { ++connectionCount; }
  );
  server_->start();
  EXPECT_EQ(connectionCount, 0);
}

TEST_F(TcpServerTest, MessageCallbackIsRegistered) {
  size_t messageCount = 0;
  server_->setMessageCallback([&messageCount](const TcpConnectionPtr &, Buffer *, TimeStamp) {
    ++messageCount;
  });
  server_->start();
  EXPECT_EQ(messageCount, 0);
}

TEST_F(TcpServerTest, WriteCompleteCallbackIsRegistered) {
  size_t writeCount = 0;
  server_->setWriteCompleteCallback([&writeCount](const TcpConnectionPtr &) { ++writeCount; });
  server_->start();
  EXPECT_EQ(writeCount, 0);
}

TEST_F(TcpServerTest, ThreadInitCallbackIsRegistered) {
  size_t initCount = 0;
  server_->setThreadInitCallback([&initCount](EventLoop *) { ++initCount; });
  server_->start();
  EXPECT_EQ(server_->numConnections(), 0);
}

TEST_F(TcpServerTest, ReusePortOptionCreatesValidServer) {
  auto reusePortServer = std::make_unique<TcpServer>(
      loop_.get(),
      InetAddress(kServerPort + 1),
      kServerName,
      TcpServer::Option::kReusePort
  );
  reusePortServer->start();
  EXPECT_EQ(reusePortServer->numConnections(), 0);
}

TEST_F(TcpServerTest, MultipleStartCallsHandledGracefully) {
  server_->start();
  server_->start();
  EXPECT_EQ(server_->numConnections(), 0);
}

TEST_F(TcpServerTest, IpPortStringFormattedCorrectly) {
  std::string expectedIpPort = std::string(kAnyIp) + ":" + std::to_string(kServerPort);
  EXPECT_EQ(server_->getIpPort(), expectedIpPort);
}

} // namespace server
