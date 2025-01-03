#pragma once

#include <cstdint>

namespace server {

class Timer;

class TimerId {
public:
  TimerId() : timer_(nullptr), sequence_(0) {}
  TimerId(Timer *timer, int64_t seq) : timer_(timer), sequence_(seq) {}

private:
  Timer *timer_;
  int64_t sequence_;

  friend class TimerQueue;
};

} // namespace server
