#pragma once

#include <cstdint>
#include <string>

namespace server {

class TimeStamp {
 public:
  TimeStamp() : microSecondsSinceEpoch_(0) {}

  explicit TimeStamp(int64_t microSecondsSinceEpoch)
      : microSecondsSinceEpoch_(microSecondsSinceEpoch) {}

  static TimeStamp now();
  static TimeStamp invalid() { return TimeStamp(); }
  bool valid() const { return microSecondsSinceEpoch_ > 0; }
  int64_t microSecondsSinceEpoch() const { return microSecondsSinceEpoch_; }
  std::string toString() const;
  std::string toFormattedString(bool showMicroseconds = true) const;

  static TimeStamp addTime(TimeStamp timestamp, double seconds) {
    int64_t delta = static_cast<int64_t>(seconds * MicroSecondsPerSecond);
    return TimeStamp(timestamp.microSecondsSinceEpoch() + delta);
  }

  bool operator<(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ < rhs.microSecondsSinceEpoch_;
  }

  bool operator==(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ == rhs.microSecondsSinceEpoch_;
  }

 private:
  static constexpr int MicroSecondsPerSecond = 1000 * 1000;
  int64_t microSecondsSinceEpoch_;
};

}  // namespace server
