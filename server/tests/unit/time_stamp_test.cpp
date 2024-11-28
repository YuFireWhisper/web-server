#include "include/time_stamp.h"

#include <gtest/gtest.h>

namespace server {

class TimeStampTest : public ::testing::Test {
protected:
  void SetUp() override {
    baseTime = TimeStamp(1000000000);
  }

  TimeStamp baseTime;
};

TEST_F(TimeStampTest, DefaultConstructorCreatesInvalidTimeStamp) {
  TimeStamp ts;
  EXPECT_FALSE(ts.valid());
  EXPECT_EQ(ts.microSecondsSinceEpoch(), 0);
}

TEST_F(TimeStampTest, ConstructorWithMicroSecondsCreatesValidTimeStamp) {
  int64_t microseconds = 1000000000;
  TimeStamp ts(microseconds);
  EXPECT_TRUE(ts.valid());
  EXPECT_EQ(ts.microSecondsSinceEpoch(), microseconds);
}

TEST_F(TimeStampTest, ArithmeticOperationsWorkCorrectly) {
  TimeStamp future = baseTime + 1.0;
  EXPECT_EQ(future.microSecondsSinceEpoch(),
            baseTime.microSecondsSinceEpoch() + TimeStamp::MicroSecondsPerSecond);

  TimeStamp past = baseTime - 1.0;
  EXPECT_EQ(past.microSecondsSinceEpoch(),
            baseTime.microSecondsSinceEpoch() - TimeStamp::MicroSecondsPerSecond);

  double diff = future - baseTime;
  EXPECT_DOUBLE_EQ(diff, 1.0);
}

TEST_F(TimeStampTest, ComparisonOperatorsWorkCorrectly) {
  TimeStamp earlier(1000000);
  TimeStamp later(2000000);

  EXPECT_TRUE(earlier < later);
  EXPECT_TRUE(earlier <= later);
  EXPECT_TRUE(later > earlier);
  EXPECT_TRUE(later >= earlier);
  EXPECT_TRUE(earlier != later);
  EXPECT_FALSE(earlier == later);
}

TEST_F(TimeStampTest, StringConversionProducesCorrectFormat) {
  TimeStamp ts(1234567890000000);
  std::string str = ts.toString();
  EXPECT_FALSE(str.empty());

  std::string formattedStr = ts.toFormattedString();
  EXPECT_FALSE(formattedStr.empty());

  std::string formattedStrNoMicro = ts.toFormattedString(false);
  EXPECT_FALSE(formattedStrNoMicro.empty());
}

TEST_F(TimeStampTest, NowReturnsValidTimeStamp) {
  TimeStamp now = TimeStamp::now();
  EXPECT_TRUE(now.valid());
}

} // namespace server
