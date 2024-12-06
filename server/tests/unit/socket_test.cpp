#include "include/buffer.h"
#include "include/inet_address.h"
#include "include/socket.h"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

namespace server {
namespace {

class NetworkTestConfig {
public:
  static constexpr uint16_t BASE_PORT = 50000;
  static constexpr int LISTEN_BACKLOG = 5;
  static constexpr auto OPERATION_TIMEOUT = std::chrono::seconds(1);
  static constexpr auto RETRY_DELAY = std::chrono::milliseconds(100);
  static constexpr int MAX_BIND_ATTEMPTS = 3;
};

class NetworkTestHelper {
public:
  static uint16_t allocatePort() { return NetworkTestConfig::BASE_PORT; }

  static bool verifyListeningPort(uint16_t port) {
    std::string netstatCmd =
        "netstat -an | grep :" + std::to_string(port) + " | grep LISTEN > /dev/null 2>&1";
    return system(netstatCmd.c_str()) == 0;
  }
};

class SocketTestFixture : public ::testing::Test {
protected:
  void TearDown() override { std::this_thread::sleep_for(std::chrono::milliseconds(500)); }

  void initializeServerSocket() {
    serverSocket_ = std::make_unique<Socket>();
    configureServerSocket();
    bindServerSocket();
  }

  Socket *getServerSocket() { return serverSocket_.get(); }

private:
  void configureServerSocket() {
    serverSocket_->enableAddressReuse();
    serverSocket_->enablePortReuse();
  }

  void bindServerSocket() {
    for (int attempt = 0; attempt < NetworkTestConfig::MAX_BIND_ATTEMPTS; ++attempt) {
      try {
        serverSocket_->bindToPort(NetworkTestHelper::allocatePort());
        serverSocket_->startListening(NetworkTestConfig::LISTEN_BACKLOG);
        return;
      } catch (const SocketException &) {
        if (attempt < NetworkTestConfig::MAX_BIND_ATTEMPTS - 1) {
          std::this_thread::sleep_for(NetworkTestConfig::RETRY_DELAY);
        } else {
          throw SocketException("Server socket binding failed after maximum attempts");
        }
      }
    }
  }

  std::unique_ptr<Socket> serverSocket_;
};

TEST_F(SocketTestFixture, createSocketSuccessfully) {
  EXPECT_NO_THROW(Socket());
}

TEST_F(SocketTestFixture, configureSocketOptionsSuccessfully) {
  Socket socket;

  EXPECT_NO_THROW({
    socket.enableAddressReuse();
    socket.enablePortReuse();
    socket.bindToPort(NetworkTestHelper::allocatePort());
    socket.enableKeepAlive();
    socket.disableNagle();
    socket.enableNonBlocking();
  });
}

TEST_F(SocketTestFixture, establishServerSocketConnection) {
  initializeServerSocket();
  auto socket = getServerSocket();

  InetAddress addr = socket->getLocalAddress();
  EXPECT_EQ(addr.getPort(), NetworkTestConfig::BASE_PORT);
  EXPECT_TRUE(NetworkTestHelper::verifyListeningPort(addr.getPort()));
}

TEST_F(SocketTestFixture, handleBufferDataOperations) {
  initializeServerSocket();
  auto socket = getServerSocket();

  uint16_t serverPort = socket->getLocalAddress().getPort();
  EXPECT_GT(serverPort, 0);
  EXPECT_TRUE(NetworkTestHelper::verifyListeningPort(serverPort));

  Buffer testBuffer;
  const std::string testMessage = "Test Message";
  testBuffer.append(testMessage);
  EXPECT_EQ(testBuffer.readableBytes(), testMessage.length());
}

TEST_F(SocketTestFixture, handleNonBlockingSocketOperations) {
  initializeServerSocket();
  auto socket = getServerSocket();

  EXPECT_NO_THROW({
    socket->enableNonBlocking();
    auto localAddr = socket->getLocalAddress();
    EXPECT_GT(localAddr.getPort(), 0);
  });
}

TEST_F(SocketTestFixture, provideAccurateConnectionInfo) {
  initializeServerSocket();
  auto socket = getServerSocket();

  auto connInfo = socket->getConnectionInfo();
  EXPECT_FALSE(socket->hasActiveConnection());
  EXPECT_FALSE(socket->hasError());

  auto localAddr = socket->getLocalAddress();
  EXPECT_GT(localAddr.getPort(), 0);
}

} // namespace
} // namespace server
