#include "include/channel.h"
#include "include/event_loop.h"

#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

namespace server::testing {

class EventLoopTest : public ::testing::Test {
protected:
  void SetUp() override {}
  void TearDown() override {}
};

TEST_F(EventLoopTest, ensureQuitStopsEventLoop) {
  bool taskCompleted = false;
  EventLoop *loop    = nullptr;

  std::thread eventLoopThread([&loop, &taskCompleted]() {
    EventLoop eventLoop;
    loop = &eventLoop;

    eventLoop.queueInLoop([&taskCompleted]() { taskCompleted = true; });

    eventLoop.loop();
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  if (loop != nullptr) {
    loop->quit();
  }

  eventLoopThread.join();
  EXPECT_TRUE(taskCompleted);
}

TEST_F(EventLoopTest, ensureQuitFromOtherThreadTriggersWakeup) {
  bool quitCompleted = false;
  EventLoop *loop    = nullptr;

  std::thread eventLoopThread([&loop]() {
    EventLoop eventLoop;
    loop = &eventLoop;
    eventLoop.loop();
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  if (loop != nullptr) {
    loop->quit();
    quitCompleted = true;
  }

  eventLoopThread.join();
  EXPECT_TRUE(quitCompleted);
}

TEST_F(EventLoopTest, ensureRunInLoopExecutesTaskInLoopThread) {
  int resultValue = 0;
  EventLoop *loop = nullptr;

  std::thread eventLoopThread([&loop, &resultValue]() {
    EventLoop eventLoop;
    loop = &eventLoop;

    eventLoop.runInLoop([&resultValue]() { resultValue = 42; });

    eventLoop.loop();
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  if (loop != nullptr) {
    loop->quit();
  }

  eventLoopThread.join();
  EXPECT_EQ(resultValue, 42);
}

TEST_F(EventLoopTest, ensureQueueInLoopPreservesTaskOrder) {
  std::vector<int> executionSequence;
  EventLoop *loop = nullptr;

  std::thread eventLoopThread([&loop, &executionSequence]() {
    EventLoop eventLoop;
    loop = &eventLoop;

    eventLoop.queueInLoop([&executionSequence]() { executionSequence.push_back(1); });

    eventLoop.queueInLoop([&executionSequence]() { executionSequence.push_back(2); });

    eventLoop.loop();
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  if (loop != nullptr) {
    loop->quit();
  }

  eventLoopThread.join();

  ASSERT_EQ(executionSequence.size(), 2);
  EXPECT_EQ(executionSequence[0], 1);
  EXPECT_EQ(executionSequence[1], 2);
}

TEST_F(EventLoopTest, ensureThreadCheckWorks) {
  EventLoop eventLoop;
  EXPECT_TRUE(eventLoop.isInLoopThread());

  bool threadCheckResult = true;
  std::thread otherThread([&]() { threadCheckResult = eventLoop.isInLoopThread(); });
  otherThread.join();

  EXPECT_FALSE(threadCheckResult);
}

TEST_F(EventLoopTest, ensureWakeupFdIdentificationWorks) {
  EventLoop eventLoop;
  int wakeupFileDescriptor = eventLoop.getWakeupFd();
  EXPECT_TRUE(eventLoop.isWakeupFd(wakeupFileDescriptor));
  EXPECT_FALSE(eventLoop.isWakeupFd(wakeupFileDescriptor + 1));
}

TEST_F(EventLoopTest, ensureChannelOperationsWork) {
  EventLoop eventLoop;
  Channel testChannel(&eventLoop, 42);

  EXPECT_NO_THROW({
    eventLoop.updateChannel(&testChannel);
    eventLoop.removeChannel(&testChannel);
  });
}

} // namespace server::testing
