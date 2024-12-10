#include "include/acceptor.h"
#include "include/channel.h"
#include "include/event_loop.h"
#include "include/inet_address.h"
#include "include/socket.h"

#include <gtest/gtest.h>
#include <memory>

namespace server::testing {

class AcceptorTest : public ::testing::Test {
protected:
  static constexpr uint16_t kDefaultTestPort = 8080;

  void SetUp() override {
    eventLoop_ = std::make_unique<EventLoop>();
    listenAddr_ = std::make_unique<InetAddress>(kDefaultTestPort);
  }

  std::unique_ptr<EventLoop> eventLoop_;
  std::unique_ptr<InetAddress> listenAddr_;
};

TEST_F(AcceptorTest, ShouldBeNotListeningWhenCreated) {
  Acceptor acceptor(eventLoop_.get(), *listenAddr_);
  EXPECT_FALSE(acceptor.isListening());
}

TEST_F(AcceptorTest, ShouldBeListeningAfterStartListen) {
  Acceptor acceptor(eventLoop_.get(), *listenAddr_);
  acceptor.startListen();
  EXPECT_TRUE(acceptor.isListening());
}

TEST_F(AcceptorTest, ShouldRemainListeningWhenStartListenCalledMultipleTimes) {
  Acceptor acceptor(eventLoop_.get(), *listenAddr_);

  acceptor.startListen();
  bool firstState = acceptor.isListening();

  acceptor.startListen();
  bool secondState = acceptor.isListening();

  EXPECT_TRUE(firstState);
  EXPECT_TRUE(secondState);
}

TEST_F(AcceptorTest, ShouldAllowSettingConnectionHandler) {
  Acceptor acceptor(eventLoop_.get(), *listenAddr_);

  bool handlerSet = false;
  acceptor.setConnectionHandler([&handlerSet](int, const InetAddress &) { handlerSet = true; });

  EXPECT_NO_THROW(acceptor.startListen());
}

TEST_F(AcceptorTest, ShouldSupportDifferentPortsInConstructor) {
  const uint16_t alternativePort = 9090;
  InetAddress alternativeAddr(alternativePort);

  EXPECT_NO_THROW({
    Acceptor acceptor(eventLoop_.get(), alternativeAddr);
    acceptor.startListen();
  });
}

TEST_F(AcceptorTest, ShouldAllowChangingConnectionHandlerAfterConstruction) {
  Acceptor acceptor(eventLoop_.get(), *listenAddr_);

  int handlerCallCount = 0;

  acceptor.setConnectionHandler([&handlerCallCount](int, const InetAddress &) {
    handlerCallCount++;
  });

  acceptor.setConnectionHandler([&handlerCallCount](int, const InetAddress &) {
    handlerCallCount += 2;
  });

  EXPECT_EQ(handlerCallCount, 0);
}

} // namespace server::testing
