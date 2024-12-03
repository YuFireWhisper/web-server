#include "include/channel.h"
#include "include/event_loop.h"
#include "include/poller.h"

#include <gtest/gtest.h>
#include <unistd.h>

#include <sys/eventfd.h>

namespace server {
namespace {

class PollerTest : public ::testing::Test {
protected:
  void SetUp() override {
    loop_ = std::make_unique<EventLoop>();
    eventFd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ASSERT_GT(eventFd_, 0);
    poller_ = loop_->getPoller();
  }

  void TearDown() override {
    if (eventFd_ > 0) {
      ::close(eventFd_);
    }
    cleanupTestFds();
  }

  int createTestFd() {
    int fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    testFds_.push_back(fd);
    return fd;
  }

  void cleanupTestFds() {
    for (int fd : testFds_) {
      ::close(fd);
    }
    testFds_.clear();
  }

  std::unique_ptr<EventLoop> loop_;
  Poller *poller_;
  int eventFd_;
  std::vector<int> testFds_;
};

TEST_F(PollerTest, ValidatesInitialState) {
  const auto &channels = poller_->getChannels();
  ASSERT_EQ(channels.size(), 1);

  auto wakeupFd = loop_->getWakeupFd();
  auto it = channels.find(wakeupFd);
  EXPECT_NE(it, channels.end());
}

TEST_F(PollerTest, RejectsNullptrChannel) {
  EXPECT_FALSE(poller_->hasChannel(nullptr));
}

TEST_F(PollerTest, RejectsUnregisteredChannel) {
  Channel channel(loop_.get(), eventFd_);
  EXPECT_FALSE(poller_->hasChannel(&channel));
}

TEST_F(PollerTest, VerifiesThreadSafety) {
  EXPECT_TRUE(loop_->isInLoopThread());
}

TEST_F(PollerTest, ManagesMultipleChannels) {
  const auto initialSize = poller_->getChannels().size();
  std::vector<std::unique_ptr<Channel>> channels;

  for (int i = 0; i < 3; ++i) {
    int fd = createTestFd();
    auto channel = std::make_unique<Channel>(loop_.get(), fd);
    channel->enableReading();
    loop_->updateChannel(channel.get());
    channels.push_back(std::move(channel));
  }

  EXPECT_EQ(poller_->getChannels().size(), initialSize + 3);

  for (const auto &channel : channels) {
    EXPECT_TRUE(poller_->hasChannel(channel.get()));
  }

  for (const auto &channel : channels) {
    loop_->removeChannel(channel.get());
  }

  EXPECT_EQ(poller_->getChannels().size(), initialSize);
}

} // namespace
} // namespace server
