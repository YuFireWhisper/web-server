#pragma once

#include "include/time_stamp.h"

#include <functional>
namespace server {
class Timer {
public:
  using TimerCallback = std::function<void()>;

  Timer(TimerCallback cb, TimeStamp when, double interval)
      : callback_(std::move(cb))
      , expiration_(when)
      , interval_(interval)
      , repeat_(interval > 0.0) {}

  void run() { callback_(); }

  void restart() { expiration_ = TimeStamp::now() + interval(); }

  [[nodiscard]] TimerCallback callback() const { return callback_; }

  [[nodiscard]] TimeStamp expiration() const { return expiration_; }
  [[nodiscard]] bool repeat() const { return repeat_; }
  [[nodiscard]] double interval() const { return interval_; }

private:
  const TimerCallback callback_;
  TimeStamp expiration_;
  const double interval_;
  const bool repeat_;
};
} // namespace server
