#include "include/event_loop_thread.h"

#include <gtest/gtest.h>

namespace server::testing {

class EventLoopThreadTest : public ::testing::Test {
public:
  void OnThreadInit(EventLoop *loop) {
    callback_loop_ = loop;
    callback_executed_ = true;
  }

protected:
  void SetUp() override {
    callback_executed_ = false;
    callback_loop_ = nullptr;
  }

  EventLoop *callback_loop_;
  bool callback_executed_;
};

TEST_F(EventLoopThreadTest, ShouldInitializeToNotRunningState) {
  EventLoopThread loop_thread;
  EXPECT_FALSE(loop_thread.isRunning());
}

TEST_F(EventLoopThreadTest, ShouldBeRunningAfterStart) {
  EventLoopThread loop_thread;
  EventLoop *loop = loop_thread.startLoop();

  ASSERT_NE(nullptr, loop);
  EXPECT_TRUE(loop_thread.isRunning());
}

TEST_F(EventLoopThreadTest, ShouldExecuteCallbackOnStart) {
  ThreadInitCallback callback = [this](auto &&PH1) {
    OnThreadInit(std::forward<decltype(PH1)>(PH1));
  };
  EventLoopThread loop_thread(callback);

  EventLoop *loop = loop_thread.startLoop();

  ASSERT_NE(nullptr, loop);
  EXPECT_TRUE(callback_executed_);
  EXPECT_EQ(loop, callback_loop_);
}

TEST_F(EventLoopThreadTest, ShouldHandleEmptyCallback) {
  ThreadInitCallback empty_callback;
  EventLoopThread loop_thread(empty_callback);
  EventLoop *loop = loop_thread.startLoop();

  ASSERT_NE(nullptr, loop);
  EXPECT_TRUE(loop_thread.isRunning());
}

TEST_F(EventLoopThreadTest, ShouldCleanupOnDestruction) {
  std::weak_ptr<EventLoopThread> weak_loop;
  {
    auto loop_thread = std::make_shared<EventLoopThread>();
    weak_loop = loop_thread;

    EventLoop *loop = loop_thread->startLoop();
    ASSERT_NE(nullptr, loop);
    EXPECT_TRUE(loop_thread->isRunning());
  }

  EXPECT_TRUE(weak_loop.expired());
}

TEST_F(EventLoopThreadTest, ShouldSupportCustomName) {
  const std::string thread_name = "TestThread";
  ThreadInitCallback empty_callback;
  EventLoopThread loop_thread(empty_callback, thread_name);

  EventLoop *loop = loop_thread.startLoop();

  ASSERT_NE(nullptr, loop);
  EXPECT_TRUE(loop_thread.isRunning());
}

TEST_F(EventLoopThreadTest, ShouldMaintainSingleInstanceOnMultipleStarts) {
  ThreadInitCallback callback = [this](auto &&PH1) {
    OnThreadInit(std::forward<decltype(PH1)>(PH1));
  };
  EventLoopThread loop_thread(callback);

  EventLoop *first_loop = loop_thread.startLoop();
  ASSERT_NE(nullptr, first_loop);

  EventLoop *second_loop = loop_thread.startLoop();
  EXPECT_EQ(first_loop, second_loop);
}

} // namespace server::testing
