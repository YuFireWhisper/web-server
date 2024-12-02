#pragma once

#include "include/types.h"

#include <cstdint>
#include <memory>
#include <mutex>

namespace server {

class EventLoop;
class TimerId;
class TimeStamp;
class Timer;

class TimerQueue {
public:
  TimerQueue(EventLoop *loop);
  TimerId addTimer(TimerCallback, TimeStamp when, double interval = 0.0);
  ~TimerQueue();

  TimeStamp nextExpiredTime() const;

  bool hasTimer() const { return !timers_.empty(); }

  int getTimeout() const;

private:
  void addTimerInLoop(Timer *timer);
  void handleRead();
  void readTimerfd();

  bool insert(Timer *timer);
  void resetTimerfd();

  std::vector<TimerEntry> getExpired();

  const int timerfd_;
  EventLoop *loop_;
  std::unique_ptr<Channel> timerfdChannel_;
  TimerList timers_;
  int64_t sequence_;

  std::mutex mutex_;
};
} // namespace server
