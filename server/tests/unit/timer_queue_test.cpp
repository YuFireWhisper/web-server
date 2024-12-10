#include "include/event_loop.h"
#include "include/time_stamp.h"
#include "include/timer_id.h"
#include "include/timer_queue.h"

#include <gtest/gtest.h>
#include <memory>
#include <vector>

namespace server::testing {

class TimerQueueTest : public ::testing::Test {
protected:
  static constexpr double kOneSecond = 1.0;
  static constexpr double kTwoSeconds = 2.0;
  static constexpr double kThreeSeconds = 3.0;
  static constexpr double kHalfSecond = 0.5;
  static constexpr int kMinTimeoutMs = 900;
  static constexpr int kMaxTimeoutMs = 1100;
  static constexpr int kTimerCount = 5;
  static constexpr size_t kCallbackCount = 3;

  void SetUp() override {
    loop_ = std::make_unique<EventLoop>();
    timerQueue_ = std::make_unique<TimerQueue>(loop_.get());
  }

  void TearDown() override {
    timerQueue_.reset();
    loop_.reset();
  }

  std::unique_ptr<EventLoop> loop_;
  std::unique_ptr<TimerQueue> timerQueue_;
};

TEST_F(TimerQueueTest, NewQueueShouldBeEmpty) {
  EXPECT_FALSE(timerQueue_->hasTimer());
  EXPECT_FALSE(timerQueue_->nextExpiredTime().valid());
  EXPECT_EQ(timerQueue_->getTimeout(), -1);
}

TEST_F(TimerQueueTest, TimersShouldBeOrderedCorrectly) {
  TimeStamp now = TimeStamp::now();
  TimeStamp time1 = now + kOneSecond;
  TimeStamp time2 = now + kTwoSeconds;
  TimeStamp time3 = now + kThreeSeconds;

  std::vector<TimeStamp> executionOrder;

  timerQueue_->addTimer([&executionOrder, time3]() { executionOrder.push_back(time3); }, time3);

  timerQueue_->addTimer([&executionOrder, time1]() { executionOrder.push_back(time1); }, time1);

  timerQueue_->addTimer([&executionOrder, time2]() { executionOrder.push_back(time2); }, time2);

  EXPECT_EQ(timerQueue_->nextExpiredTime(), time1);
}

TEST_F(TimerQueueTest, TimeoutCalculationShouldBeAccurate) {
  TimeStamp now = TimeStamp::now();
  TimeStamp future = now + kOneSecond;

  timerQueue_->addTimer([]() {}, future);

  int timeout = timerQueue_->getTimeout();
  EXPECT_GE(timeout, kMinTimeoutMs);
  EXPECT_LE(timeout, kMaxTimeoutMs);
}

TEST_F(TimerQueueTest, ShouldHandleInvalidTimestamp) {
  TimeStamp invalidTime;
  bool callbackCalled = false;

  timerQueue_->addTimer([&callbackCalled]() { callbackCalled = true; }, invalidTime);

  EXPECT_FALSE(callbackCalled);
  EXPECT_EQ(timerQueue_->getTimeout(), -1);
}

TEST_F(TimerQueueTest, TimerShouldHaveCorrectProperties) {
  TimeStamp now = TimeStamp::now();
  TimeStamp triggerTime = now + kOneSecond;
  bool called = false;

  timerQueue_->addTimer([&called]() { called = true; }, triggerTime, kHalfSecond);

  EXPECT_TRUE(timerQueue_->hasTimer());
  EXPECT_EQ(timerQueue_->nextExpiredTime(), triggerTime);
}

TEST_F(TimerQueueTest, ShouldHandleMultipleTimers) {
  TimeStamp now = TimeStamp::now();
  std::vector<TimerId> timerIds;

  for (int i = 0; i < kTimerCount; ++i) {
    TimeStamp triggerTime = now + static_cast<double>(i);
    timerIds.push_back(timerQueue_->addTimer([]() {}, triggerTime));
  }

  EXPECT_TRUE(timerQueue_->hasTimer());
  EXPECT_EQ(timerQueue_->nextExpiredTime(), now + 0.0);
}

TEST_F(TimerQueueTest, ShouldHandleEdgeCases) {
  TimeStamp now = TimeStamp::now();
  TimeStamp sameTime = now + kOneSecond;
  std::vector<bool> callbacks(kCallbackCount, false);

  for (auto &&callback : callbacks) {
    timerQueue_->addTimer([&callback]() { callback = true; }, sameTime);
  }

  EXPECT_EQ(timerQueue_->nextExpiredTime(), sameTime);
}

} // namespace server::testing
