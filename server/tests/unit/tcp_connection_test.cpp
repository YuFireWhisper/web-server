#include "include/event_loop.h"
#include "include/log.h"
#include "include/tcp_connection.h"

#include <array>
#include <csignal>
#include <future>
#include <gtest/gtest.h>

namespace server::testing {

namespace {
constexpr int DEFAULT_SERVER_PORT = 1234;
constexpr int DEFAULT_CLIENT_PORT = 4321;
constexpr size_t BUFFER_SIZE      = 1024;
constexpr int TIMEOUT_SECONDS     = 5;
} // namespace

void ignoreSigPipe() {
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags   = 0;
  sigaction(SIGPIPE, &sa, nullptr);
}

class SocketPair {
public:
  SocketPair() {
    std::array<int, 2> sockets{};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) < 0) {
      throw std::runtime_error("Failed to create socket pair");
    }
    serverSocket = std::make_unique<Socket>(sockets[0]);
    clientSocket = std::make_unique<Socket>(sockets[1]);

    serverSocket->enableNonBlocking();
    clientSocket->enableNonBlocking();
  }

  std::unique_ptr<Socket> releaseServer() { return std::move(serverSocket); }

  [[nodiscard]] int getClientFd() const { return clientSocket ? clientSocket->getSocketFd() : -1; }

private:
  std::unique_ptr<Socket> serverSocket;
  std::unique_ptr<Socket> clientSocket;
};

class TcpConnectionTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() { ignoreSigPipe(); }

  void SetUp() override {
    std::promise<EventLoop *> loopPromise;
    auto loopFuture = loopPromise.get_future();

    loopThread = std::thread([this, &loopPromise]() {
      auto localLoop = std::make_unique<EventLoop>();
      loop           = localLoop.get();
      loopPromise.set_value(loop);
      loop->loop();
    });

    loop = loopFuture.get();

    std::promise<void> initPromise;
    auto initFuture = initPromise.get_future();

    loop->runInLoop([this, &initPromise]() {
      sockets  = std::make_unique<SocketPair>();
      clientFd = sockets->getClientFd();

      connection = std::make_shared<TcpConnection>(
          loop,
          "test-connection",
          sockets->releaseServer(),
          InetAddress(DEFAULT_SERVER_PORT),
          InetAddress("127.0.0.1", DEFAULT_CLIENT_PORT)
      );
      initPromise.set_value();
    });

    initFuture.wait();
  }

  void TearDown() override {
    if (connection && (loop != nullptr)) {
      std::promise<void> promise;
      auto future = promise.get_future();

      loop->runInLoop([this, &promise]() {
        if (connection) {
          connection->connectDestroyed();
          connection.reset();
        }
        promise.set_value();
      });

      future.wait();
    }

    if (loop != nullptr) {
      loop->quit();
    }

    if (loopThread.joinable()) {
      loopThread.join();
    }

    loop = nullptr;
  }

  template <typename F>
  void runInLoop(F &&fn) {
    std::promise<void> promise;
    auto future = promise.get_future();

    Logger::log(LogLevel::INFO, "Queuing task in event loop");

    loop->queueInLoop([fn = std::forward<F>(fn), &promise]() mutable {
      Logger::log(LogLevel::INFO, "Executing task in event loop");
      fn();
      Logger::log(LogLevel::INFO, "Task completed, setting promise");
      promise.set_value();
    });

    Logger::log(LogLevel::INFO, "Waiting for task completion");
    auto status = future.wait_for(std::chrono::seconds(TIMEOUT_SECONDS));
    ASSERT_EQ(std::future_status::ready, status)
        << "Task in event loop did not complete within " << TIMEOUT_SECONDS << " seconds";
    Logger::log(LogLevel::INFO, "Task completed successfully");
  }

  std::thread loopThread;
  EventLoop *loop{nullptr};
  std::shared_ptr<TcpConnection> connection;
  std::unique_ptr<SocketPair> sockets;
  int clientFd{-1};
};

TEST_F(TcpConnectionTest, ShouldProvideConnectionInfo) {
  EXPECT_FALSE(connection->connected());
  EXPECT_EQ(connection->name(), "test-connection");
  EXPECT_EQ(connection->getLoop(), loop);
  EXPECT_EQ(connection->localAddress().getPort(), DEFAULT_SERVER_PORT);
  EXPECT_EQ(connection->peerAddress().getPort(), DEFAULT_CLIENT_PORT);
}

TEST_F(TcpConnectionTest, ShouldHandleConnectionLifecycle) {
  std::promise<bool> establishedPromise;
  std::promise<bool> destroyedPromise;

  runInLoop([&]() {
    connection->setConnectionCallback([&](const TcpConnectionPtr &conn) {
      if (conn->connected()) {
        establishedPromise.set_value(true);
      } else {
        destroyedPromise.set_value(true);
      }
    });
    connection->connectEstablished();
  });

  EXPECT_TRUE(establishedPromise.get_future().get());
  EXPECT_TRUE(connection->connected());

  runInLoop([&]() { connection->connectDestroyed(); });

  EXPECT_TRUE(destroyedPromise.get_future().get());
  EXPECT_FALSE(connection->connected());
}

TEST_F(TcpConnectionTest, ShouldHandleMessageSendingWithString) {
  std::promise<void> writeComplete;
  const std::string testMessage = "Test String Message";

  runInLoop([&]() {
    connection->setWriteCompleteCallback([&](const TcpConnectionPtr &) {
      writeComplete.set_value();
    });
    connection->connectEstablished();
    connection->send(testMessage);
  });

  writeComplete.get_future().wait();

  std::array<char, BUFFER_SIZE> buffer{};
  ssize_t bytesRead = read(clientFd, buffer.data(), buffer.size());
  EXPECT_GT(bytesRead, 0);
  EXPECT_EQ(std::string(buffer.data(), bytesRead), testMessage);
}

TEST_F(TcpConnectionTest, ShouldHandleMessageSendingWithStringView) {
  std::promise<void> writeComplete;
  const std::string_view testMessage = "Test StringView Message";

  runInLoop([&]() {
    connection->setWriteCompleteCallback([&](const TcpConnectionPtr &) {
      writeComplete.set_value();
    });
    connection->connectEstablished();
    connection->send(testMessage);
  });

  writeComplete.get_future().wait();

  std::array<char, BUFFER_SIZE> buffer{};
  ssize_t bytesRead = read(clientFd, buffer.data(), buffer.size());
  EXPECT_GT(bytesRead, 0);
  EXPECT_EQ(std::string(buffer.data(), bytesRead), std::string(testMessage));
}

TEST_F(TcpConnectionTest, ShouldHandleMessageSendingWithBuffer) {
  std::promise<void> writeComplete;
  Buffer sendBuffer;
  const std::string testMessage = "Test Buffer Message";
  sendBuffer.append(testMessage);

  runInLoop([&]() {
    connection->setWriteCompleteCallback([&](const TcpConnectionPtr &) {
      writeComplete.set_value();
    });
    connection->connectEstablished();
    connection->send(&sendBuffer);
  });

  writeComplete.get_future().wait();

  std::array<char, BUFFER_SIZE> buffer{};
  ssize_t bytesRead = read(clientFd, buffer.data(), buffer.size());
  EXPECT_GT(bytesRead, 0);
  EXPECT_EQ(std::string(buffer.data(), bytesRead), testMessage);
}

TEST_F(TcpConnectionTest, ShouldHandleMessageReceiving) {
  std::promise<std::string> messageReceived;

  runInLoop([&]() {
    connection->setMessageCallback(
        [&messageReceived](const TcpConnectionPtr &, Buffer *buffer, TimeStamp) {
          messageReceived.set_value(buffer->retrieveAllAsString());
        }
    );
    connection->connectEstablished();
  });

  std::string testMessage = "Hello, World!";
  write(clientFd, testMessage.c_str(), testMessage.length());

  auto receivedMessage = messageReceived.get_future().get();
  EXPECT_EQ(receivedMessage, testMessage);
}

TEST_F(TcpConnectionTest, ShouldHandleHighWaterMark) {
  std::promise<size_t> waterMarkReached;
  const size_t waterMark    = 64;
  const size_t testDataSize = waterMark * 2;

  auto future = waterMarkReached.get_future();

  Logger::log(LogLevel::INFO, "Starting high water mark test");

  runInLoop([&]() {
    connection->setHighWaterMarkCallback(
        [&](const TcpConnectionPtr &, size_t size) {
          Logger::log(
              LogLevel::INFO,
              "High water mark callback triggered with size: " + std::to_string(size)
          );
          waterMarkReached.set_value(size);
        },
        waterMark
    );

    connection->connectEstablished();
    connection->send(std::string(testDataSize, 'X'));
  });

  auto status = future.wait_for(std::chrono::seconds(TIMEOUT_SECONDS));
  ASSERT_EQ(std::future_status::ready, status)
      << "High water mark callback not triggered within timeout";

  size_t size = future.get();
  EXPECT_GT(size, waterMark);
}

TEST_F(TcpConnectionTest, ShouldHandleGracefulShutdown) {
  std::promise<void> shutdownComplete;
  auto future = shutdownComplete.get_future();

  runInLoop([&]() {
    connection->setCloseCallback([&](const TcpConnectionPtr &) {
      Logger::log(LogLevel::INFO, "Shutdown complete callback triggered");
      shutdownComplete.set_value();
    });
    connection->connectEstablished();
    connection->shutdown();
  });

  auto status = future.wait_for(std::chrono::seconds(TIMEOUT_SECONDS));
  ASSERT_EQ(std::future_status::ready, status) << "Shutdown did not complete within timeout";
  EXPECT_FALSE(connection->connected());
}

TEST_F(TcpConnectionTest, ShouldHandleForceClose) {
  std::promise<void> closeComplete;

  runInLoop([&]() {
    connection->setCloseCallback([&](const TcpConnectionPtr &) { closeComplete.set_value(); });
    connection->connectEstablished();
    connection->forceClose();
  });

  closeComplete.get_future().wait();
  EXPECT_FALSE(connection->connected());
}

} // namespace server::testing
