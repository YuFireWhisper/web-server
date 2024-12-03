#include "include/channel.h"
#include "include/event_loop.h"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

namespace server {
namespace testing {

class EventLoopTest : public ::testing::Test {
protected:
  void SetUp() override { eventLoop_ = std::make_unique<EventLoop>(); }

  void TearDown() override { eventLoop_.reset(); }

  std::unique_ptr<EventLoop> eventLoop_;
};

TEST_F(EventLoopTest, ensureQuitStopsEventLoop) {
  bool taskCompleted = false;

  std::thread eventLoopThread([this]() { eventLoop_->loop(); });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  eventLoop_->queueInLoop([&taskCompleted]() { taskCompleted = true; });

  eventLoop_->queueInLoop([this]() { eventLoop_->quit(); });

  eventLoopThread.join();
  EXPECT_TRUE(taskCompleted);
}

TEST_F(EventLoopTest, ensureQuitFromOtherThreadTriggersWakeup) {
  bool quitCompleted = false;

  std::thread workerThread([this, &quitCompleted]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    eventLoop_->quit();
    quitCompleted = true;
  });

  eventLoop_->loop();
  workerThread.join();

  EXPECT_TRUE(quitCompleted);
}

TEST_F(EventLoopTest, ensureRunInLoopExecutesTaskInLoopThread) {
  int resultValue = 0;

  std::thread eventLoopThread([this]() { eventLoop_->loop(); });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  eventLoop_->runInLoop([&resultValue]() { resultValue = 42; });

  eventLoop_->queueInLoop([this]() { eventLoop_->quit(); });

  eventLoopThread.join();
  EXPECT_EQ(resultValue, 42);
}

TEST_F(EventLoopTest, ensureQueueInLoopPreservesTaskOrder) {
  std::vector<int> executionSequence;

  std::thread eventLoopThread([this]() { eventLoop_->loop(); });

  eventLoop_->queueInLoop([&executionSequence]() { executionSequence.push_back(1); });

  eventLoop_->queueInLoop([&executionSequence, this]() {
    executionSequence.push_back(2);
    eventLoop_->quit();
  });

  eventLoopThread.join();

  ASSERT_EQ(executionSequence.size(), 2);
  EXPECT_EQ(executionSequence[0], 1);
  EXPECT_EQ(executionSequence[1], 2);
}

TEST_F(EventLoopTest, ensureThreadCheckWorks) {
  EXPECT_TRUE(eventLoop_->isInLoopThread());

  std::thread otherThread([this]() { EXPECT_FALSE(eventLoop_->isInLoopThread()); });

  otherThread.join();
}

TEST_F(EventLoopTest, ensureWakeupFdIdentificationWorks) {
  int wakeupFileDescriptor = eventLoop_->getWakeupFd();
  EXPECT_TRUE(eventLoop_->isWakeupFd(wakeupFileDescriptor));
  EXPECT_FALSE(eventLoop_->isWakeupFd(wakeupFileDescriptor + 1));
}

TEST_F(EventLoopTest, ensureChannelOperationsWork) {
  Channel testChannel(eventLoop_.get(), 42);

  EXPECT_NO_THROW({
    eventLoop_->updateChannel(&testChannel);
    eventLoop_->removeChannel(&testChannel);
  });
}

} // namespace testing
} // namespace server
