#include <gtest/gtest.h>
#include "include/channel.h"
#include "include/event_loop.h"
#include "include/time_stamp.h"
#include <fcntl.h>

namespace server {

class ChannelTest : public ::testing::Test {
protected:
    void SetUp() override {
        loop_ = std::make_unique<EventLoop>();
        test_fd_ = ::open("/dev/null", O_RDONLY);
        ASSERT_GT(test_fd_, 0);
        channel_ = std::make_unique<Channel>(loop_.get(), test_fd_);
    }

    void TearDown() override {
        channel_.reset();
        ::close(test_fd_);
        loop_.reset();
    }

    int test_fd_;
    std::unique_ptr<EventLoop> loop_;
    std::unique_ptr<Channel> channel_;
};

TEST_F(ChannelTest, InitialState) {
    EXPECT_EQ(channel_->fd(), test_fd_);
    EXPECT_TRUE(channel_->isNoneEvent());
    EXPECT_FALSE(channel_->isReading());
    EXPECT_FALSE(channel_->isWriting());
    EXPECT_EQ(channel_->ownerLoop(), loop_.get());
}

TEST_F(ChannelTest, EnableAndDisableReading) {
    channel_->enableReading();
    EXPECT_TRUE(channel_->isReading());
    EXPECT_FALSE(channel_->isWriting());
    EXPECT_FALSE(channel_->isNoneEvent());

    channel_->disableReading();
    EXPECT_FALSE(channel_->isReading());
    EXPECT_TRUE(channel_->isNoneEvent());
}

TEST_F(ChannelTest, EnableAndDisableWriting) {
    channel_->enableWriting();
    EXPECT_TRUE(channel_->isWriting());
    EXPECT_FALSE(channel_->isReading());
    EXPECT_FALSE(channel_->isNoneEvent());

    channel_->disableWriting();
    EXPECT_FALSE(channel_->isWriting());
    EXPECT_TRUE(channel_->isNoneEvent());
}

TEST_F(ChannelTest, EnableAndDisableAll) {
    channel_->enableReading();
    channel_->enableWriting();
    EXPECT_TRUE(channel_->isReading());
    EXPECT_TRUE(channel_->isWriting());

    channel_->disableAll();
    EXPECT_TRUE(channel_->isNoneEvent());
    EXPECT_FALSE(channel_->isReading());
    EXPECT_FALSE(channel_->isWriting());
}

TEST_F(ChannelTest, EventCallbacks) {
    TimeStamp test_time;
    bool read_triggered = false;
    bool write_triggered = false;
    bool error_triggered = false;
    bool close_triggered = false;

    channel_->setReadCallback([&](TimeStamp) { read_triggered = true; });
    channel_->setWriteCallback([&]() { write_triggered = true; });
    channel_->setErrorCallback([&]() { error_triggered = true; });
    channel_->setCloseCallback([&]() { close_triggered = true; });

    channel_->set_revents(POLLIN | POLLPRI);
    channel_->handleEvent(test_time);
    EXPECT_TRUE(read_triggered);

    channel_->set_revents(POLLOUT);
    channel_->handleEvent(test_time);
    EXPECT_TRUE(write_triggered);

    channel_->set_revents(POLLERR);
    channel_->handleEvent(test_time);
    EXPECT_TRUE(error_triggered);

    channel_->set_revents(POLLHUP);
    channel_->handleEvent(test_time);
    EXPECT_TRUE(close_triggered);
}

TEST_F(ChannelTest, HandleEventWithGuard) {
    TimeStamp test_time;
    bool callback_triggered = false;
    channel_->setReadCallback([&](TimeStamp) { callback_triggered = true; });
    
    channel_->set_revents(POLLIN);
    channel_->handleEventWithGuard(test_time);
    EXPECT_TRUE(callback_triggered);
}

TEST_F(ChannelTest, IndexManagement) {
    const int test_index = 5;
    channel_->set_index(test_index);
    EXPECT_EQ(channel_->index(), test_index);
}

TEST_F(ChannelTest, ThreadAffinity) {
    EXPECT_TRUE(channel_->isInLoop());
    channel_->assertInLoop();
}

TEST_F(ChannelTest, ChannelRemoval) {
    channel_->enableReading();
    EXPECT_FALSE(channel_->isNoneEvent());
    
    channel_->disableAll();
    EXPECT_TRUE(channel_->isNoneEvent());
    channel_->remove();
}

} // namespace server
