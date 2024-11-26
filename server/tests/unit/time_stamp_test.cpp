#include "include/time_stamp.h"
#include <gtest/gtest.h>

namespace server {

TEST(TimeStampTest, Now) {
  TimeStamp ts = TimeStamp::now();
  EXPECT_NE(ts.toString(), "invalid");
}

TEST(TimeStampTest, ToString) {
  TimeStamp ts(1609459200000000); // 2021-01-01 00:00:00 UTC
  EXPECT_EQ(ts.toString(), "1609459200.000000");
}

TEST(TimeStampTest, ToFormattedStringWithMicroseconds) {
  TimeStamp ts(1609459200123456); // 2021-01-01 00:00:00.123456 UTC
  EXPECT_EQ(ts.toFormattedString(true), "20210101 00:00:00.123456");
}

TEST(TimeStampTest, ToFormattedStringWithoutMicroseconds) {
  TimeStamp ts(1609459200123456); // 2021-01-01 00:00:00.123456 UTC
  EXPECT_EQ(ts.toFormattedString(false), "20210101 00:00:00");
}

}  // namespace server

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

