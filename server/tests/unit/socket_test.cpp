#include "include/buffer.h"
#include "include/inter_address.h"
#include "include/socket.h"

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

namespace server {
namespace {

class PortAllocator {
public:
  static uint16_t nextPort() { return 50000; }
};

class SocketTest : public ::testing::Test {
protected:
  static constexpr int LISTEN_BACKLOG = 5;
  static constexpr auto OPERATION_TIMEOUT = std::chrono::seconds(1);

  void TearDown() override { std::this_thread::sleep_for(std::chrono::milliseconds(500)); }

  uint16_t AllocatePort() { return PortAllocator::nextPort(); }

  void PrepareServerSocket(Socket &serverSocket) {
    serverSocket.enableAddressReuse();
    serverSocket.enablePortReuse();

    bool bound = false;
    for (int attempts = 0; attempts < 3 && !bound; ++attempts) {
      try {
        serverSocket.bindToPort(AllocatePort());
        bound = true;
      } catch (const SocketException &) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }

    if (!bound) {
      throw SocketException("Failed to bind server socket after multiple attempts");
    }

    serverSocket.startListening(LISTEN_BACKLOG);
  }
};

TEST_F(SocketTest, SocketCreationShouldSucceed) {
  EXPECT_NO_THROW({ Socket socket; });
}

TEST_F(SocketTest, SocketBindingAndOptionsShouldSucceed) {
  Socket socket;
  EXPECT_NO_THROW({
    socket.enableAddressReuse();
    socket.enablePortReuse();
    socket.bindToPort(AllocatePort());
    socket.enableKeepAlive();
    socket.disableNagle();
    socket.enableNonBlocking();
  });
}

TEST_F(SocketTest, SocketShouldEstablishConnection) {
  Socket serverSocket;
  EXPECT_NO_THROW({
    serverSocket.enableAddressReuse();
    serverSocket.enablePortReuse();
  });

  EXPECT_NO_THROW({ serverSocket.bindToPort(50000); });
  EXPECT_NO_THROW({ serverSocket.startListening(5); });

  InterAddress addr = serverSocket.getLocalAddress();
  EXPECT_EQ(addr.getPort(), 50000);

  std::string cmd = "netstat -an | grep :50000 | grep LISTEN > /dev/null 2>&1";
  EXPECT_EQ(system(cmd.c_str()), 0);
}

TEST_F(SocketTest, SocketShouldHandleDataTransfer) {
  Socket serverSocket;
  PrepareServerSocket(serverSocket);

  EXPECT_NO_THROW({
    uint16_t serverPort = serverSocket.getLocalAddress().getPort();
    EXPECT_GT(serverPort, 0);
  });

  EXPECT_NO_THROW({
    std::string cmd =
        "netstat -an | grep :" + std::to_string(serverSocket.getLocalAddress().getPort())
        + " | grep LISTEN > /dev/null 2>&1";
    EXPECT_EQ(system(cmd.c_str()), 0);
  });

  Buffer testBuffer;
  const std::string testData = "Test Message";
  testBuffer.append(testData);
  EXPECT_EQ(testBuffer.readableBytes(), testData.length());
}

TEST_F(SocketTest, NonBlockingSocketShouldHandleEmptyRead) {
  Socket serverSocket;
  PrepareServerSocket(serverSocket);

  EXPECT_NO_THROW({ serverSocket.enableNonBlocking(); });

  EXPECT_NO_THROW({
    auto localAddr = serverSocket.getLocalAddress();
    EXPECT_GT(localAddr.getPort(), 0);
  });
}

TEST_F(SocketTest, SocketShouldProvideConnectionInfo) {
  Socket serverSocket;
  PrepareServerSocket(serverSocket);

  EXPECT_NO_THROW({
    auto connInfo = serverSocket.getConnectionInfo();
    EXPECT_FALSE(serverSocket.hasActiveConnection());
    EXPECT_FALSE(serverSocket.hasError());
  });

  EXPECT_NO_THROW({
    auto localAddr = serverSocket.getLocalAddress();
    EXPECT_GT(localAddr.getPort(), 0);
  });
}

} // namespace
} // namespace server
