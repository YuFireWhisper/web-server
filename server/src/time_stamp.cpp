#include "include/time_stamp.h"

#include "include/types.h"

#include <array>
#include <cinttypes>
#include <ctime>

namespace server {

namespace {
constexpr int kBufferSize32 = 32;
constexpr int kBufferSize64 = 64;
constexpr int kYearOffset = 1900;
} // namespace

TimeStamp TimeStamp::now() {
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return TimeStamp::invalid();
  }

  int64_t microSecondsSinceEpoch = (ts.tv_sec * MicroSecondsPerSecond)
                                   + (ts.tv_nsec / (kNanosecondPerSecond / MicroSecondsPerSecond));
  return TimeStamp(microSecondsSinceEpoch);
}

std::string TimeStamp::toString() const {
  std::array<char, kBufferSize32> buf{};
  int64_t seconds = microSecondsSinceEpoch_ / MicroSecondsPerSecond;
  int64_t microseconds = microSecondsSinceEpoch_ % MicroSecondsPerSecond;
  snprintf(buf.data(), buf.size() - 1, "%" PRId64 ".%06" PRId64 "", seconds, microseconds);
  return buf.data();
}

std::string TimeStamp::toFormattedString(bool showMicroseconds) const {
  std::array<char, kBufferSize64> buf{};
  auto seconds = static_cast<time_t>(microSecondsSinceEpoch_ / MicroSecondsPerSecond);
  struct tm tm_time;
  gmtime_r(&seconds, &tm_time);

  if (showMicroseconds) {
    int microseconds = static_cast<int>(microSecondsSinceEpoch_ % MicroSecondsPerSecond);
    snprintf(
        buf.data(),
        buf.size(),
        "%04d%02d%02d %02d:%02d:%02d.%06d",
        tm_time.tm_year + kYearOffset,
        tm_time.tm_mon + 1,
        tm_time.tm_mday,
        tm_time.tm_hour,
        tm_time.tm_min,
        tm_time.tm_sec,
        microseconds
    );
  } else {
    snprintf(
        buf.data(),
        buf.size(),
        "%04d%02d%02d %02d:%02d:%02d",
        tm_time.tm_year + kYearOffset,
        tm_time.tm_mon + 1,
        tm_time.tm_mday,
        tm_time.tm_hour,
        tm_time.tm_min,
        tm_time.tm_sec
    );
  }

  return buf.data();
}

} // namespace server
