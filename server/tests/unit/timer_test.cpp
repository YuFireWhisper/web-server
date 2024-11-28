#include "include/timer.h"

#include <gtest/gtest.h>

namespace server {

class TimerTest : public ::testing::Test {
protected:
  void SetUp() override {
    callbackCalled = false;
    callback = [this]() { callbackCalled = true; };
    now = TimeStamp::now();
  }

  bool callbackCalled;
  Timer::TimerCallback callback;
  TimeStamp now;
};

TEST_F(TimerTest, ConstructorInitializesTimer) {
  Timer timer(callback, now, 1.0);
  EXPECT_EQ(timer.expiration(), now);
  EXPECT_DOUBLE_EQ(timer.interval(), 1.0);
  EXPECT_TRUE(timer.repeat());
}

TEST_F(TimerTest, NonRepeatingTimerHasCorrectState) {
  Timer timer(callback, now, 0.0);
  EXPECT_FALSE(timer.repeat());
}

TEST_F(TimerTest, RunExecutesCallback) {
  Timer timer(callback, now, 1.0);
  EXPECT_FALSE(callbackCalled);
  timer.run();
  EXPECT_TRUE(callbackCalled);
}

TEST_F(TimerTest, RestartUpdatesTimer) {
  Timer timer(callback, now, 1.0);
  TimeStamp originalExpiration = timer.expiration();
  timer.restart();

  Timer newTimer = Timer(timer.callback(), timer.expiration(), timer.interval());
  EXPECT_GT(newTimer.expiration(), originalExpiration);
}

} // namespace server
