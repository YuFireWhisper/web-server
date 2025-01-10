#include "include/event_loop.h"
#include "include/event_loop_thread.h"

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

namespace server::testing {

class EventLoopThreadTest : public ::testing::Test {
protected:
  void SetUp() override {}
  void TearDown() override {}
};

TEST_F(EventLoopThreadTest, BasicLifecycle) {
  EventLoopThread loopThread;
  EXPECT_FALSE(loopThread.isRunning());

  loopThread.startLoop();
  EXPECT_TRUE(loopThread.isRunning());

  loopThread.stop();
  EXPECT_FALSE(loopThread.isRunning());
}

TEST_F(EventLoopThreadTest, MultipleStartShouldBeIdempotent) {
  EventLoopThread loopThread;
  EXPECT_FALSE(loopThread.isRunning());

  loopThread.startLoop();
  EXPECT_TRUE(loopThread.isRunning());

  loopThread.startLoop();
  EXPECT_TRUE(loopThread.isRunning());

  loopThread.stop();
  EXPECT_FALSE(loopThread.isRunning());
}

TEST_F(EventLoopThreadTest, ThreadInitCallbackShouldExecute) {
  bool callbackExecuted = false;
  EventLoopThread loopThread([&callbackExecuted](EventLoop *) { callbackExecuted = true; });

  EXPECT_FALSE(callbackExecuted);
  loopThread.startLoop();

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  EXPECT_TRUE(callbackExecuted);

  loopThread.stop();
}

TEST_F(EventLoopThreadTest, StopShouldBeIdempotent) {
  EventLoopThread loopThread;

  loopThread.startLoop();
  EXPECT_TRUE(loopThread.isRunning());

  loopThread.stop();
  EXPECT_FALSE(loopThread.isRunning());

  loopThread.stop();
  EXPECT_FALSE(loopThread.isRunning());
}

TEST_F(EventLoopThreadTest, DestructorShouldStopThread) {
  bool threadStopped = false;
  {
    EventLoopThread loopThread([&threadStopped](EventLoop *loop) {
      loop->runInLoop([&threadStopped]() { threadStopped = true; });
    });

    loopThread.startLoop();
    EXPECT_TRUE(loopThread.isRunning());

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  EXPECT_TRUE(threadStopped);
}

TEST_F(EventLoopThreadTest, ConcurrentStartStop) {
  EventLoopThread loopThread;
  std::atomic<int> successfulStarts{ 0 };
  std::atomic<int> successfulStops{ 0 };
  std::atomic<int> attempts{ 0 };

  std::vector<std::thread> threads;
  const int numThreads = 4;

  threads.reserve(numThreads);
  for (int i = 0; i < numThreads; ++i) {
    threads.emplace_back([&]() {
      attempts++;
      EventLoop *loop = loopThread.startLoop();
      if (loop != nullptr) {
        successfulStarts++;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        loopThread.stop();
        successfulStops++;
      }
    });
  }

  for (auto &t : threads) {
    t.join();
  }

  EXPECT_EQ(numThreads, attempts);
  EXPECT_EQ(1, successfulStarts);
  EXPECT_EQ(1, successfulStops);
  EXPECT_FALSE(loopThread.isRunning());
}
} // namespace server::testing
