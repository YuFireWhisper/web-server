#include "include/time_stamp.h"
#include "include/timer.h"
#include "include/timer_id.h"

#include <gtest/gtest.h>

namespace server {

class TimerIdTest : public ::testing::Test {
protected:
  void SetUp() override {
    callback = []() {};
    timer = new Timer(callback, TimeStamp::now(), 0.0);
    sequence = 1;
  }

  void TearDown() override {
    delete timer;
  }

  Timer::TimerCallback callback;
  Timer *timer;
  int64_t sequence;
};

TEST_F(TimerIdTest, DefaultConstructorCreatesEmptyTimerId) {
  TimerId id;
  EXPECT_EQ(sizeof(id), sizeof(Timer *) + sizeof(int64_t));
}

TEST_F(TimerIdTest, ConstructorWithParametersStoresValues) {
  TimerId id(timer, sequence);
  EXPECT_EQ(sizeof(id), sizeof(Timer *) + sizeof(int64_t));
}

TEST_F(TimerIdTest, DifferentTimerIdsAreIndependent) {
  TimerId id1(timer, sequence);
  TimerId id2(timer, sequence + 1);
  EXPECT_NE(&id1, &id2);
}

} // namespace server
