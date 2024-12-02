#include "include/channel.h"
#include "include/event_loop.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

namespace server {
namespace testing {

class EventLoopTest : public ::testing::Test {
protected:
  void SetUp() override { loop_ = std::make_unique<EventLoop>(); }

  void TearDown() override { loop_.reset(); }

  std::unique_ptr<EventLoop> loop_;
};

TEST_F(EventLoopTest, QuitStopsEventLoop) {
  bool taskExecuted = false;
  std::thread loopThread([&]() { loop_->loop(); });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  loop_->queueInLoop([&taskExecuted]() { taskExecuted = true; });
  loop_->queueInLoop([this]() { loop_->quit(); });

  loopThread.join();

  EXPECT_TRUE(taskExecuted);
}

TEST_F(EventLoopTest, CrossThreadQuitTriggersWakeup) {
  bool loopExited = false;

  std::thread worker([this, &loopExited]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    loop_->quit();
    loopExited = true;
  });

  loop_->loop();
  worker.join();

  EXPECT_TRUE(loopExited);
}

TEST_F(EventLoopTest, RunInLoopExecutesTask) {
  int taskValue = 0;

  std::thread loopThread([&]() { loop_->loop(); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  loop_->runInLoop([&taskValue]() { taskValue = 42; });
  loop_->queueInLoop([this]() { loop_->quit(); });

  loopThread.join();

  EXPECT_EQ(taskValue, 42);
}

TEST_F(EventLoopTest, QueueInLoopPreservesOrder) {
  std::vector<int> executionOrder;

  std::thread loopThread([&]() { loop_->loop(); });

  loop_->queueInLoop([&]() { executionOrder.push_back(1); });

  loop_->queueInLoop([&]() {
    executionOrder.push_back(2);
    loop_->quit();
  });

  loopThread.join();

  ASSERT_EQ(executionOrder.size(), 2);
  EXPECT_EQ(executionOrder[0], 1);
  EXPECT_EQ(executionOrder[1], 2);
}

TEST_F(EventLoopTest, IsInLoopThreadReturnsTrueInSameThread) {
  EXPECT_TRUE(loop_->isInLoopThread());
}

TEST_F(EventLoopTest, IsWakeupFdIdentifiesWakeupFileDescriptor) {
  int wakeupFd = loop_->getWakeupFd();
  EXPECT_TRUE(loop_->isWakeupFd(wakeupFd));
  EXPECT_FALSE(loop_->isWakeupFd(wakeupFd + 1));
}

TEST_F(EventLoopTest, UpdateChannelForwardsToPoller) {
  Channel testChannel(loop_.get(), 42);
  EXPECT_NO_FATAL_FAILURE(loop_->updateChannel(&testChannel));
}

TEST_F(EventLoopTest, RemoveChannelForwardsToPoller) {
  Channel testChannel(loop_.get(), 42);
  EXPECT_NO_FATAL_FAILURE(loop_->removeChannel(&testChannel));
}

} // namespace testing
} // namespace server
