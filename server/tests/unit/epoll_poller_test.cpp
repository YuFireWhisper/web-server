#include "include/channel.h"
#include "include/epoll_poller.h"
#include "include/event_loop.h"

#include <gtest/gtest.h>
#include <memory>

#include <sys/eventfd.h>

namespace server::testing {

class EPollPollerTest : public ::testing::Test {
protected:
  void SetUp() override {
    eventFd_ = createEventFd();
    ASSERT_GT(eventFd_, 0);

    loop_ = std::make_unique<EventLoop>();
    poller_ = dynamic_cast<EPollPoller *>(loop_->getPoller());
    ASSERT_NE(poller_, nullptr);

    channel_ = std::make_unique<Channel>(loop_.get(), eventFd_);
  }

  void TearDown() override {
    channel_.reset();
    if (eventFd_ > 0) {
      ::close(eventFd_);
      eventFd_ = -1;
    }
  }

  static int createEventFd() { return ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); }

  void triggerEvent() const {
    uint64_t one = 1;
    ASSERT_EQ(write(eventFd_, &one, sizeof(one)), sizeof(one));
  }

  void readEvent() const {
    uint64_t value;
    ASSERT_EQ(read(eventFd_, &value, sizeof(value)), sizeof(value));
  }

  std::unique_ptr<EventLoop> loop_;
  EPollPoller *poller_;
  std::unique_ptr<Channel> channel_;
  int eventFd_{-1};
};

TEST_F(EPollPollerTest, initChannelStateIsNew) {
  EXPECT_EQ(channel_->index(), static_cast<int>(PollerState::kNew));
  EXPECT_FALSE(poller_->hasChannel(channel_.get()));
}

TEST_F(EPollPollerTest, enableReadingWillAddChannel) {
  channel_->enableReading();
  EXPECT_TRUE(poller_->hasChannel(channel_.get()));
  EXPECT_EQ(channel_->index(), static_cast<int>(PollerState::kAdded));
}

TEST_F(EPollPollerTest, disableAllWillRemoveChannel) {
  channel_->enableReading();
  ASSERT_TRUE(poller_->hasChannel(channel_.get()));

  channel_->disableAll();
  channel_->remove();
  EXPECT_FALSE(poller_->hasChannel(channel_.get()));
  EXPECT_EQ(channel_->index(), static_cast<int>(PollerState::kNew));
}

TEST_F(EPollPollerTest, handlesMultipleChannels) {
  std::vector<int> fds;
  std::vector<std::unique_ptr<Channel>> channels;
  const int CHANNEL_COUNT = 3;

  for (int i = 0; i < CHANNEL_COUNT; ++i) {
    int fd = createEventFd();
    ASSERT_GT(fd, 0);
    fds.push_back(fd);

    auto channel = std::make_unique<Channel>(loop_.get(), fd);
    channel->enableReading();
    EXPECT_TRUE(poller_->hasChannel(channel.get()));
    channels.push_back(std::move(channel));
  }

  for (int fd : fds) {
    uint64_t one = 1;
    ASSERT_EQ(write(fd, &one, sizeof(one)), sizeof(one));
  }

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);
  EXPECT_EQ(activeChannels.size(), CHANNEL_COUNT);

  for (int fd : fds) {
    uint64_t value;
    ASSERT_EQ(read(fd, &value, sizeof(value)), sizeof(value));
    ::close(fd);
  }
}

TEST_F(EPollPollerTest, handlesReadEvent) {
  bool eventHandled = false;
  channel_->setReadCallback([&eventHandled](TimeStamp) { eventHandled = true; });
  channel_->enableReading();

  triggerEvent();

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);
  ASSERT_EQ(activeChannels.size(), 1);

  activeChannels[0]->handleEvent(TimeStamp::now());
  EXPECT_TRUE(eventHandled);

  readEvent();
}

TEST_F(EPollPollerTest, handlesWriteEvent) {
  bool eventHandled = false;
  channel_->setWriteCallback([&eventHandled]() { eventHandled = true; });
  channel_->enableWriting();

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);

  if (!activeChannels.empty()) {
    activeChannels[0]->handleEvent(TimeStamp::now());
    EXPECT_TRUE(eventHandled);
  }
}

TEST_F(EPollPollerTest, ignoresInvalidFileDescriptor) {
  int invalidFd = -1;
  Channel invalidChannel(loop_.get(), invalidFd);
  EXPECT_FALSE(poller_->hasChannel(&invalidChannel));

  invalidChannel.enableReading();
  EXPECT_FALSE(poller_->hasChannel(&invalidChannel));
}

TEST_F(EPollPollerTest, handlesRepeatedOperations) {
  channel_->enableReading();
  EXPECT_TRUE(poller_->hasChannel(channel_.get()));

  channel_->enableReading();
  EXPECT_TRUE(poller_->hasChannel(channel_.get()));

  channel_->disableAll();
  channel_->remove();
  EXPECT_FALSE(poller_->hasChannel(channel_.get()));

  channel_->remove();
  EXPECT_FALSE(poller_->hasChannel(channel_.get()));
}

TEST_F(EPollPollerTest, channelStateTransitions) {
  EXPECT_EQ(channel_->index(), static_cast<int>(PollerState::kNew));

  channel_->enableReading();
  EXPECT_EQ(channel_->index(), static_cast<int>(PollerState::kAdded));

  channel_->disableAll();
  EXPECT_EQ(channel_->index(), static_cast<int>(PollerState::kDeleted));

  channel_->remove();
  EXPECT_EQ(channel_->index(), static_cast<int>(PollerState::kNew));
}

TEST_F(EPollPollerTest, eventDataIsCorrect) {
  channel_->enableReading();
  triggerEvent();

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);

  ASSERT_FALSE(activeChannels.empty());
  EXPECT_EQ(activeChannels[0]->fd(), eventFd_);
  EXPECT_TRUE(activeChannels[0]->isReading());

  readEvent();
}

TEST_F(EPollPollerTest, pollTimeoutWorks) {
  channel_->enableReading();

  ChannelList activeChannels;
  auto start = TimeStamp::now();

  const static int timeoutMs = 100;
  poller_->poll(timeoutMs, &activeChannels);
  auto end = TimeStamp::now();

  EXPECT_GE(end.microSecondsSinceEpoch() - start.microSecondsSinceEpoch(), 100 * 1000);
}

} // namespace server::testing
