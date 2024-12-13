#include "include/event_loop.h"
#include "include/event_loop_thread.h"
#include "include/event_loop_thread_pool.h"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

namespace server::testing {

class EventLoopThreadPoolTest : public ::testing::Test {
protected:
  void SetUp() override { baseLoop_ = std::make_unique<EventLoop>(); }

  void TearDown() override { baseLoop_.reset(); }

  std::unique_ptr<EventLoop> baseLoop_;
};

TEST_F(EventLoopThreadPoolTest, ConstructWithValidBaseLoop) {
  EventLoopThreadPool pool(baseLoop_.get());
  EXPECT_FALSE(pool.isStarted());
  EXPECT_EQ(pool.name(), "");
}

TEST_F(EventLoopThreadPoolTest, ConstructWithNameAndValidBaseLoop) {
  EventLoopThreadPool pool(baseLoop_.get(), "TestPool");
  EXPECT_FALSE(pool.isStarted());
  EXPECT_EQ(pool.name(), "TestPool");
}

TEST_F(EventLoopThreadPoolTest, ThrowsExceptionWhenBaseLoopIsNull) {
  EXPECT_THROW(EventLoopThreadPool(nullptr), std::invalid_argument);
}

TEST_F(EventLoopThreadPoolTest, StartWithZeroThreadsUsesSystemThreads) {
  EventLoopThreadPool pool(baseLoop_.get());
  pool.setThreadNum(0);
  pool.start();

  EXPECT_TRUE(pool.isStarted());
  auto loops = pool.getAllLoops();

  size_t expectedThreads = std::thread::hardware_concurrency();
  EXPECT_EQ(loops.size(), expectedThreads);

  for (auto *loop : loops) {
    EXPECT_NE(loop, nullptr);
    EXPECT_NE(loop, baseLoop_.get());
  }
}

TEST_F(EventLoopThreadPoolTest, StartWithMultipleThreads) {
  EventLoopThreadPool pool(baseLoop_.get());
  pool.setThreadNum(3);
  pool.start();

  EXPECT_TRUE(pool.isStarted());
  auto loops = pool.getAllLoops();
  EXPECT_EQ(loops.size(), 3);

  for (auto *loop : loops) {
    EXPECT_NE(loop, nullptr);
    EXPECT_NE(loop, baseLoop_.get());
  }
}

TEST_F(EventLoopThreadPoolTest, GetNextLoopWithRoundRobin) {
  EventLoopThreadPool pool(baseLoop_.get());
  pool.setThreadNum(3);
  pool.start();

  auto loops = pool.getAllLoops();
  EXPECT_EQ(loops.size(), 3);

  auto *loop1 = pool.getNextLoop();
  auto *loop2 = pool.getNextLoop();
  auto *loop3 = pool.getNextLoop();
  auto *loop4 = pool.getNextLoop();

  EXPECT_EQ(loop1, loops[0]);
  EXPECT_EQ(loop2, loops[1]);
  EXPECT_EQ(loop3, loops[2]);
  EXPECT_EQ(loop4, loops[0]);
}

TEST_F(EventLoopThreadPoolTest, GetLoopForHashWithConsistentResults) {
  EventLoopThreadPool pool(baseLoop_.get());
  pool.setThreadNum(3);
  pool.start();

  auto loops                    = pool.getAllLoops();
  const static size_t hashCode1 = 100;
  const static size_t hashCode2 = 101;

  auto *loop1      = pool.getLoopForHash(hashCode1);
  auto *loop2      = pool.getLoopForHash(hashCode2);
  auto *loop1Again = pool.getLoopForHash(hashCode1);

  EXPECT_EQ(loop1, loops[hashCode1 % 3]);
  EXPECT_EQ(loop2, loops[hashCode2 % 3]);
  EXPECT_EQ(loop1, loop1Again);
}

TEST_F(EventLoopThreadPoolTest, GetAllLoopsBeforeStart) {
  EventLoopThreadPool pool(baseLoop_.get());
  pool.setThreadNum(3);

  auto loops = pool.getAllLoops();
  EXPECT_TRUE(loops.empty());
}

TEST_F(EventLoopThreadPoolTest, ThreadInitCallbackInvocation) {
  EventLoopThreadPool pool(baseLoop_.get());
  pool.setThreadNum(2);

  int callbackCount = 0;
  auto callback     = [&callbackCount](EventLoop *loop) {
    EXPECT_NE(loop, nullptr);
    ++callbackCount;
  };

  pool.start(callback);
  const static int sleepTime = 100;
  std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));

  EXPECT_EQ(callbackCount, 3); // 2 threads + baseLoop
}

} // namespace server::testing
