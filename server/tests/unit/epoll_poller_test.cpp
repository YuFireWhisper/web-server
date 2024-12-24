#include "include/channel.h"
#include "include/epoll_poller.h"
#include "include/event_loop.h"
#include "include/time_stamp.h"

#include <gtest/gtest.h>

#include <sys/socket.h>

namespace server::testing {

class EPollPollerTest : public ::testing::Test {
protected:
  void SetUp() override {
    loop_   = std::make_unique<EventLoop>();
    poller_ = std::make_unique<EPollPoller>(loop_.get());
  }

  void TearDown() override {
    poller_.reset();
    loop_.reset();
  }

  std::unique_ptr<EventLoop> loop_;
  std::unique_ptr<EPollPoller> poller_;
};

TEST_F(EPollPollerTest, PollWithNoEventsReturnsImmediately) {
  ChannelList activeChannels;
  TimeStamp before = TimeStamp::now();
  TimeStamp result = poller_->poll(0, &activeChannels);
  TimeStamp after  = TimeStamp::now();

  EXPECT_TRUE(result >= before);
  EXPECT_TRUE(result <= after);
  EXPECT_TRUE(activeChannels.empty());
}

TEST_F(EPollPollerTest, AddChannelSuccessfully) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GT(fd, 0);

  Channel channel(loop_.get(), fd);
  channel.enableReading();

  EXPECT_NO_THROW(poller_->updateChannel(&channel));
  EXPECT_TRUE(poller_->hasChannel(&channel));

  ::close(fd);
}

TEST_F(EPollPollerTest, UpdateExistingChannel) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GT(fd, 0);

  Channel channel(loop_.get(), fd);
  channel.enableReading();
  poller_->updateChannel(&channel);

  channel.enableWriting();
  EXPECT_NO_THROW(poller_->updateChannel(&channel));
  EXPECT_TRUE(poller_->hasChannel(&channel));

  ::close(fd);
}

TEST_F(EPollPollerTest, RemoveChannelSuccessfully) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GT(fd, 0);

  Channel channel(loop_.get(), fd);
  channel.enableReading();
  poller_->updateChannel(&channel);

  EXPECT_NO_THROW(poller_->removeChannel(&channel));
  EXPECT_FALSE(poller_->hasChannel(&channel));

  ::close(fd);
}

TEST_F(EPollPollerTest, RemoveNonexistentChannelIsNoop) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GT(fd, 0);

  Channel channel(loop_.get(), fd);
  EXPECT_NO_THROW(poller_->removeChannel(&channel));
  EXPECT_FALSE(poller_->hasChannel(&channel));

  ::close(fd);
}

TEST_F(EPollPollerTest, UpdateChannelToNoneEventRemovesFromPoller) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GT(fd, 0);

  Channel channel(loop_.get(), fd);
  channel.enableReading();
  poller_->updateChannel(&channel);

  channel.disableAll();
  poller_->updateChannel(&channel);
  EXPECT_FALSE(poller_->hasChannel(&channel));

  ::close(fd);
}

TEST_F(EPollPollerTest, PollDetectsReadableSocket) {
  int fds[2];
  ASSERT_EQ(::pipe(fds), 0);

  Channel channel(loop_.get(), fds[0]);
  channel.enableReading();
  poller_->updateChannel(&channel);

  const char data[] = "test";
  ASSERT_EQ(::write(fds[1], data, sizeof(data)), sizeof(data));

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);

  EXPECT_FALSE(activeChannels.empty());
  EXPECT_EQ(activeChannels[0], &channel);

  ::close(fds[0]);
  ::close(fds[1]);
}

TEST_F(EPollPollerTest, PollDetectsWritableSocket) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GT(fd, 0);

  Channel channel(loop_.get(), fd);
  channel.enableWriting();
  poller_->updateChannel(&channel);

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);

  EXPECT_FALSE(activeChannels.empty());
  EXPECT_EQ(activeChannels[0], &channel);

  ::close(fd);
}

TEST_F(EPollPollerTest, EventListResizesWhenNeeded) {
  std::vector<int> fds;
  std::vector<std::unique_ptr<Channel>> channels;
  const int numChannels = 32;

  for (int i = 0; i < numChannels; ++i) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GT(fd, 0);
    fds.push_back(fd);

    auto channel = std::make_unique<Channel>(loop_.get(), fd);
    channel->enableWriting();
    poller_->updateChannel(channel.get());
    channels.push_back(std::move(channel));
  }

  ChannelList activeChannels;
  EXPECT_NO_THROW(poller_->poll(0, &activeChannels));
  EXPECT_EQ(activeChannels.size(), numChannels);

  for (int fd : fds) {
    ::close(fd);
  }
}

TEST_F(EPollPollerTest, MultipleEventsOnSameChannel) {
  int fds[2];
  ASSERT_EQ(::pipe(fds), 0);

  Channel channel(loop_.get(), fds[0]);
  channel.enableReading();
  channel.enableWriting();
  poller_->updateChannel(&channel);

  const char data[] = "test";
  ASSERT_EQ(::write(fds[1], data, sizeof(data)), sizeof(data));

  ChannelList activeChannels;
  poller_->poll(0, &activeChannels);

  EXPECT_FALSE(activeChannels.empty());
  EXPECT_EQ(activeChannels[0], &channel);

  ::close(fds[0]);
  ::close(fds[1]);
}

} // namespace server::testing
