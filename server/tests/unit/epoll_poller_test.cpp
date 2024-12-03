#include "include/channel.h"
#include "include/epoll_poller.h"
#include "include/event_loop.h"
#include "include/log.h"
#include "include/types.h"

#include <gtest/gtest.h>
#include <memory>

#include <sys/eventfd.h>

namespace server {
namespace testing {

class EPollPollerTest : public ::testing::Test {
protected:
  void SetUp() override {
    loop_ = std::make_unique<EventLoop>();
    poller_ = std::make_unique<EPollPoller>(loop_.get());
    efd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ASSERT_GT(efd_, 0) << "Failed to create event fd";
  }

  void TearDown() override {
    if (efd_ > 0) {
      ::close(efd_);
    }
  }

  int CreateEventFd() {
    int evtfd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evtfd < 0) {
      ADD_FAILURE() << "Failed to create event fd";
      return -1;
    }
    return evtfd;
  }

  void TriggerEvent(int fd) {
    uint64_t one = 1;
    ASSERT_EQ(write(fd, &one, sizeof(one)), sizeof(one));
  }

  void ReadEvent(int fd) {
    uint64_t value;
    ASSERT_EQ(read(fd, &value, sizeof(value)), sizeof(value));
  }

  std::unique_ptr<EventLoop> loop_;
  std::unique_ptr<EPollPoller> poller_;
  int efd_;
};

TEST_F(EPollPollerTest, InitialChannelStateIsNew) {
  Channel channel(loop_.get(), efd_);
  EXPECT_EQ(channel.index(), static_cast<int>(PollerState::kNew));
  EXPECT_FALSE(poller_->hasChannel(&channel));
}

TEST_F(EPollPollerTest, EnableReadingShouldAddChannel) {
  auto poller = dynamic_cast<EPollPoller *>(loop_->getPoller());

  Channel channel(loop_.get(), efd_);
  Logger::log(LogLevel::DEBUG, "Test: Created channel with fd = " + std::to_string(efd_));

  channel.enableReading();

  Logger::log(
      LogLevel::DEBUG,
      "Test: Checking channel with ptr = " + std::to_string((uintptr_t)&channel)
  );

  EXPECT_TRUE(poller->hasChannel(&channel));
}

TEST_F(EPollPollerTest, DisableAllShouldRemoveChannel) {
  auto poller = dynamic_cast<EPollPoller *>(loop_->getPoller());

  Channel channel(loop_.get(), efd_);
  channel.enableReading();
  ASSERT_TRUE(poller->hasChannel(&channel));

  channel.disableAll();
  channel.remove();

  EXPECT_FALSE(poller->hasChannel(&channel));
  EXPECT_EQ(channel.index(), static_cast<int>(PollerState::kNew));
}

TEST_F(EPollPollerTest, ShouldHandleMultipleChannels) {
  auto poller = dynamic_cast<EPollPoller *>(loop_->getPoller());

  std::vector<std::unique_ptr<Channel>> channels;
  std::vector<int> fds;
  const int kChannelCount = 3;

  for (int i = 0; i < kChannelCount; ++i) {
    fds.push_back(CreateEventFd());
    channels.push_back(std::make_unique<Channel>(loop_.get(), fds.back()));
    channels.back()->enableReading();
    EXPECT_TRUE(poller->hasChannel(channels.back().get()));
  }

  for (int fd : fds) {
    TriggerEvent(fd);
  }

  ChannelList activeChannels;
  poller->poll(0, &activeChannels);
  EXPECT_EQ(activeChannels.size(), kChannelCount);

  for (int fd : fds) {
    ReadEvent(fd);
    ::close(fd);
  }
}

TEST_F(EPollPollerTest, ShouldHandleReadEvents) {
  auto poller = dynamic_cast<EPollPoller*>(loop_->getPoller());
  
  bool eventHandled = false;
  Channel channel(loop_.get(), efd_);
  channel.setReadCallback([&eventHandled](TimeStamp) { eventHandled = true; });
  channel.enableReading();
  
  TriggerEvent(efd_);

  ChannelList activeChannels;
  poller->poll(0, &activeChannels);
  
  ASSERT_EQ(activeChannels.size(), 1);
  
  activeChannels[0]->handleEvent(TimeStamp::now());
  EXPECT_TRUE(eventHandled);
  
  ReadEvent(efd_);
}

TEST_F(EPollPollerTest, ShouldHandleWriteEvents) {
  bool eventHandled = false;
  Channel channel(loop_.get(), efd_);

  channel.setWriteCallback([&eventHandled]() { eventHandled = true; });

  channel.enableWriting();

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);

  if (!activeChannels.empty()) {
    activeChannels[0]->handleEvent(TimeStamp::now());
    EXPECT_TRUE(eventHandled);
  }
}

TEST_F(EPollPollerTest, ShouldIgnoreInvalidFileDescriptor) {
  Channel channel(loop_.get(), -1);
  EXPECT_FALSE(poller_->hasChannel(&channel));

  channel.enableReading();
  EXPECT_FALSE(poller_->hasChannel(&channel));
}

TEST_F(EPollPollerTest, ShouldHandleRepeatedOperations) {
  auto poller = dynamic_cast<EPollPoller*>(loop_->getPoller());
  
  Channel channel(loop_.get(), efd_);

  channel.enableReading();
  EXPECT_TRUE(poller->hasChannel(&channel));
  
  channel.enableReading();
  EXPECT_TRUE(poller->hasChannel(&channel));

  channel.disableAll();
  channel.remove();
  EXPECT_FALSE(poller->hasChannel(&channel));
  
  channel.remove();
  EXPECT_FALSE(poller->hasChannel(&channel));
}

} // namespace testing
} // namespace server
