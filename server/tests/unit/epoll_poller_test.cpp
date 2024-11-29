#include "include/channel.h"
#include "include/epoll_poller.h"
#include "include/event_loop.h"
#include "include/time_stamp.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace server {
namespace testing {

class MockChannel : public Channel {
public:
  explicit MockChannel(EventLoop *loop, int fd) : Channel(loop, fd) {}
  MOCK_METHOD(int, events, (), (const));
  MOCK_METHOD(void, set_revents, (int revents));
};

class MockEventLoop : public EventLoop {
public:
};

class MockEPollLogger : public EPollLogger {
public:
};

class EPollPollerTest : public ::testing::Test {
protected:
  void SetUp() override {
    eventLoop_ = std::make_unique<MockEventLoop>();
    poller_ = std::make_unique<EPollPoller>(eventLoop_.get());
  }

  void TearDown() override {
    poller_.reset();
    eventLoop_.reset();
  }

  std::unique_ptr<MockChannel> createMockChannel(int fd) {
    return std::make_unique<MockChannel>(eventLoop_.get(), fd);
  }

  std::unique_ptr<MockEventLoop> eventLoop_;
  std::unique_ptr<EPollPoller> poller_;
};

TEST_F(EPollPollerTest, ConstructorSucceeds) {
  EXPECT_NO_THROW({ EPollPoller poller(eventLoop_.get()); });
}

TEST_F(EPollPollerTest, UpdateNewChannel) {
  auto channel = createMockChannel(1);

  EXPECT_CALL(*channel, events()).WillRepeatedly(::testing::Return(EPOLLIN));

  EXPECT_FALSE(poller_->hasChannel(channel.get()));
  EXPECT_NO_THROW(poller_->updateChannel(channel.get()));
  EXPECT_TRUE(poller_->hasChannel(channel.get()));
}

TEST_F(EPollPollerTest, UpdateExistingChannel) {
  auto channel = createMockChannel(1);

  EXPECT_CALL(*channel, events()).WillRepeatedly(::testing::Return(EPOLLIN));

  poller_->updateChannel(channel.get());

  EXPECT_NO_THROW(poller_->updateChannel(channel.get()));
  EXPECT_TRUE(poller_->hasChannel(channel.get()));
}

TEST_F(EPollPollerTest, RemoveExistingChannel) {
  auto channel = createMockChannel(1);

  EXPECT_CALL(*channel, events()).WillRepeatedly(::testing::Return(EPOLLIN));

  poller_->updateChannel(channel.get());
  EXPECT_TRUE(poller_->hasChannel(channel.get()));

  EXPECT_NO_THROW(poller_->removeChannel(channel.get()));
  EXPECT_FALSE(poller_->hasChannel(channel.get()));
}

TEST_F(EPollPollerTest, RemoveNonExistingChannel) {
  auto channel = createMockChannel(1);

  EXPECT_FALSE(poller_->hasChannel(channel.get()));
  EXPECT_THROW(poller_->removeChannel(channel.get()), std::runtime_error);
}

TEST_F(EPollPollerTest, PollWithNoEvents) {
  ChannelList activeChannels;
  TimeStamp now = TimeStamp::now();

  ::testing::internal::CaptureStdout();
  TimeStamp result = poller_->poll(0, &activeChannels);
  ::testing::internal::GetCapturedStdout();

  EXPECT_TRUE(activeChannels.empty());
}

TEST_F(EPollPollerTest, HasChannelReturnsFalseForNullptr) {
  EXPECT_FALSE(poller_->hasChannel(nullptr));
}

class EPollEventManagerTest : public ::testing::Test {
protected:
  void SetUp() override {
    eventLoop_ = std::make_unique<MockEventLoop>();
    epollfd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epollfd_ < 0) {
      throw std::runtime_error("Failed to create epoll fd in test");
    }
    manager_ = std::make_unique<EPollEventManager>(epollfd_);
  }

  void TearDown() override {
    manager_.reset();
    if (epollfd_ >= 0) {
      ::close(epollfd_);
    }
    eventLoop_.reset();
  }

  std::unique_ptr<MockChannel> createMockChannel(int fd) {
    return std::make_unique<MockChannel>(eventLoop_.get(), fd);
  }

  std::unique_ptr<MockEventLoop> eventLoop_;
  int epollfd_ = -1;
  std::unique_ptr<EPollEventManager> manager_;
};

TEST_F(EPollEventManagerTest, AddChannel) {
  auto channel = createMockChannel(1);

  EXPECT_CALL(*channel, events()).WillRepeatedly(::testing::Return(EPOLLIN));

  EXPECT_NO_THROW(manager_->addChannel(channel.get()));
  EXPECT_TRUE(manager_->hasChannel(channel.get()));
}

TEST_F(EPollEventManagerTest, ModifyChannel) {
  auto channel = createMockChannel(1);

  EXPECT_CALL(*channel, events()).WillRepeatedly(::testing::Return(EPOLLIN));

  manager_->addChannel(channel.get());
  EXPECT_NO_THROW(manager_->modifyChannel(channel.get()));
}

TEST_F(EPollEventManagerTest, RemoveChannel) {
  auto channel = createMockChannel(1);

  EXPECT_CALL(*channel, events()).WillRepeatedly(::testing::Return(EPOLLIN));

  manager_->addChannel(channel.get());
  EXPECT_NO_THROW(manager_->removeChannel(channel.get()));
  EXPECT_FALSE(manager_->hasChannel(channel.get()));
}

} // namespace testing
} // namespace server
