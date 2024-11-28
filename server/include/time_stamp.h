#pragma once

#include <cstdint>
#include <string>

namespace server {

class TimeStamp {
public:
  static constexpr int MicroSecondsPerSecond = 1000 * 1000;

  TimeStamp() : microSecondsSinceEpoch_(0) {}

  explicit TimeStamp(int64_t microSecondsSinceEpoch)
      : microSecondsSinceEpoch_(microSecondsSinceEpoch) {}

  static TimeStamp now();
  static TimeStamp invalid() {
    return TimeStamp();
  }
  bool valid() const {
    return microSecondsSinceEpoch_ > 0;
  }
  int64_t microSecondsSinceEpoch() const {
    return microSecondsSinceEpoch_;
  }
  std::string toString() const;
  std::string toFormattedString(bool showMicroseconds = true) const;

  double secondsSinceEpoch() const {
    return static_cast<double>(microSecondsSinceEpoch_) / MicroSecondsPerSecond;
  }

  TimeStamp operator+(double seconds) const {
    int64_t delta = static_cast<int64_t>(seconds * MicroSecondsPerSecond);
    return TimeStamp(microSecondsSinceEpoch_ + delta);
  }

  TimeStamp operator-(double seconds) const {
    int64_t delta = static_cast<int64_t>(seconds * MicroSecondsPerSecond);
    return TimeStamp(microSecondsSinceEpoch_ - delta);
  }

  double operator-(const TimeStamp &rhs) const {
    int64_t diff = microSecondsSinceEpoch_ - rhs.microSecondsSinceEpoch_;
    return static_cast<double>(diff) / MicroSecondsPerSecond;
  }

  bool operator>(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ > rhs.microSecondsSinceEpoch_;
  }

  bool operator>=(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ >= rhs.microSecondsSinceEpoch_;
  }

  bool operator!=(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ != rhs.microSecondsSinceEpoch_;
  }

  bool operator<(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ < rhs.microSecondsSinceEpoch_;
  }

  bool operator<=(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ < rhs.microSecondsSinceEpoch_;
  }

  bool operator==(TimeStamp rhs) const {
    return microSecondsSinceEpoch_ == rhs.microSecondsSinceEpoch_;
  }

private:
  int64_t microSecondsSinceEpoch_;
};

inline TimeStamp operator+(double seconds, const TimeStamp &timestamp) {
  return timestamp + seconds;
}

} // namespace server
