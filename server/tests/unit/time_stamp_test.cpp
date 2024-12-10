#include "include/time_stamp.h"
#include "include/types.h"

#include <gtest/gtest.h>

namespace server {

namespace {
constexpr int64_t kBaseTestTime = static_cast<int64_t>(1000) * kMicroSecondsPerSecond;
constexpr int64_t kTestTime1 = 1000 * kBaseTestTime;
constexpr int64_t kTestTime2 = 2000 * kBaseTestTime;
constexpr int64_t kLargeTestTime = 1234567890LL * kMicroSecondsPerSecond;
} // namespace

class TimeStampTest : public ::testing::Test {
protected:
  void SetUp() override { baseTime = TimeStamp(kBaseTestTime); }

  TimeStamp baseTime;
};

TEST_F(TimeStampTest, DefaultConstructorCreatesInvalidTimeStamp) {
  TimeStamp ts;
  EXPECT_FALSE(ts.valid());
  EXPECT_EQ(ts.microSecondsSinceEpoch(), 0);
}

TEST_F(TimeStampTest, ConstructorWithMicroSecondsCreatesValidTimeStamp) {
  TimeStamp ts(kBaseTestTime);
  EXPECT_TRUE(ts.valid());
  EXPECT_EQ(ts.microSecondsSinceEpoch(), kBaseTestTime);
}

TEST_F(TimeStampTest, ArithmeticOperationsWorkCorrectly) {
  TimeStamp future = baseTime + 1.0;
  EXPECT_EQ(
      future.microSecondsSinceEpoch(),
      baseTime.microSecondsSinceEpoch() + kMicroSecondsPerSecond
  );

  TimeStamp past = baseTime - 1.0;
  EXPECT_EQ(
      past.microSecondsSinceEpoch(),
      baseTime.microSecondsSinceEpoch() - kMicroSecondsPerSecond
  );

  double diff = future - baseTime;
  EXPECT_DOUBLE_EQ(diff, 1.0);
}

TEST_F(TimeStampTest, ComparisonOperatorsWorkCorrectly) {
  TimeStamp earlier(kTestTime1);
  TimeStamp later(kTestTime2);

  EXPECT_TRUE(earlier < later);
  EXPECT_TRUE(earlier <= later);
  EXPECT_TRUE(later > earlier);
  EXPECT_TRUE(later >= earlier);
  EXPECT_TRUE(earlier != later);
  EXPECT_FALSE(earlier == later);
}

TEST_F(TimeStampTest, StringConversionProducesCorrectFormat) {
  TimeStamp ts(kLargeTestTime);
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
