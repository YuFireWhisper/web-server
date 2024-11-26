#include "include/time_stamp.h"

#include <inttypes.h>

#include <ctime>

namespace server {
TimeStamp TimeStamp::now() {
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return TimeStamp::invalid();
  }

  int64_t microSecondsSinceEpoch =
      ts.tv_sec * MicroSecondsPerSecond + ts.tv_nsec / 1000;
  return TimeStamp(microSecondsSinceEpoch);
}

std::string TimeStamp::toString() const {
  char buf[32] = {0};
  int64_t seconds = microSecondsSinceEpoch_ / MicroSecondsPerSecond;
  int64_t microseconds = microSecondsSinceEpoch_ % MicroSecondsPerSecond;
  snprintf(buf, sizeof(buf) - 1, "%" PRId64 ".%06" PRId64 "", seconds,
           microseconds);
  return buf;
}

std::string TimeStamp::toFormattedString(bool showMicroseconds) const {
  char buf[64] = {0};
  time_t seconds =
      static_cast<time_t>(microSecondsSinceEpoch_ / MicroSecondsPerSecond);
  struct tm tm_time;
  gmtime_r(&seconds, &tm_time);

  if (showMicroseconds) {
    int microseconds =
        static_cast<int>(microSecondsSinceEpoch_ % MicroSecondsPerSecond);
    snprintf(buf, sizeof(buf), "%04d%02d%02d %02d:%02d:%02d.%06d",
             tm_time.tm_year + 1900, tm_time.tm_mon + 1, tm_time.tm_mday,
             tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec, microseconds);
  } else {
    snprintf(buf, sizeof(buf), "%04d%02d%02d %02d:%02d:%02d",
             tm_time.tm_year + 1900, tm_time.tm_mon + 1, tm_time.tm_mday,
             tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
  }

  return buf;
}

}  // namespace server
