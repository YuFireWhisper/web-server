#include "include/timer_queue.h"

#include "include/channel.h"
#include "include/event_loop.h"
#include "include/log.h"
#include "include/time_stamp.h"
#include "include/timer.h"
#include "include/timer_id.h"
#include "include/types.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>

#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>

namespace server {

TimerQueue::TimerQueue(EventLoop *loop)
    : timerfd_(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC))
    , loop_(loop)
    , sequence_(0) {
  log_detail::Logger::setDefaultOutputFile("time_queue.log");

  if (timerfd_ < 0) {
    LOG_FATAL("Timerfd create error");
    abort();
  }
  timerfdChannel_ = std::make_unique<Channel>(loop, timerfd_);
  timerfdChannel_->setReadCallback([this](TimeStamp) { handleRead(); });
  timerfdChannel_->enableReading();
}

TimerQueue::~TimerQueue() {
  ::close(timerfd_);
  for (const TimerEntry &timer : timers_) {
    delete timer.second;
  }
}

TimerId TimerQueue::addTimer(TimerCallback cb, TimeStamp when, double interval) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto *timer = new Timer(std::move(cb), when, interval);
  TimerId id(timer, sequence_++);
  loop_->runInLoop([this, timer] { addTimerInLoop(timer); });
  return id;
}

void TimerQueue::addTimerInLoop(Timer *timer) {
  loop_->assertInLoopThread();
  bool earliestChange = insert(timer);
  if (earliestChange) {
    resetTimerfd();
  }
}

bool TimerQueue::insert(Timer *timer) {
  bool earliestChanged = false;
  TimeStamp when       = timer->expiration();
  auto it              = timers_.begin();

  if (it == timers_.end() || when < it->first) {
    earliestChanged = true;
  }

  timers_.insert(TimerEntry(when, timer));

  return earliestChanged;
}

void TimerQueue::resetTimerfd() {
  loop_->assertInLoopThread();

  if (timers_.empty()) {
    struct itimerspec newValue;
    memset(&newValue, 0, sizeof(newValue));
    int ret = ::timerfd_settime(timerfd_, 0, &newValue, nullptr);
    if (ret < 0) {
      LOG_ERROR("timerfd_settime() failed");
    }
    return;
  }

  TimeStamp earliestTime = timers_.begin()->first;
  TimeStamp now          = TimeStamp::now();

  int64_t microsendconds = earliestTime.microSecondsSinceEpoch() - now.microSecondsSinceEpoch();
  microsendconds         = std::max<int64_t>(microsendconds, microsendconds);

  struct itimerspec newValue;
  memset(&newValue, 0, sizeof(newValue));
  newValue.it_value.tv_sec = static_cast<time_t>(microsendconds / kMicroSecondsPerSecond);
  newValue.it_value.tv_nsec =
      static_cast<long>((microsendconds % kMicroSecondsPerSecond) * kTimeScaleFactor);

  int ret = ::timerfd_settime(timerfd_, 0, &newValue, nullptr);
  if (ret < 0) {
    LOG_ERROR("timerfd_settime() failed");
  }
}

void TimerQueue::handleRead() {
  loop_->assertInLoopThread();
  readTimerfd();

  std::vector<TimerEntry> expired = getExpired();
  for (const TimerEntry &it : expired) {
    it.second->run();

    if (it.second->repeat()) {
      it.second->restart();
      insert(it.second);
    } else {
      delete it.second;
    }
  }

  resetTimerfd();
}

std::vector<TimerEntry> TimerQueue::getExpired() {
  TimeStamp now = TimeStamp::now();
  TimerEntry sentry(now, nullptr);
  auto end = timers_.lower_bound(sentry);
  std::vector<TimerEntry> expried(timers_.begin(), end);
  timers_.erase(timers_.begin(), end);
  return expried;
}

void TimerQueue::readTimerfd() const {
  uint64_t howmany;

  ssize_t result = ::read(timerfd_, &howmany, sizeof howmany);

  if (result != sizeof(howmany)) {
    std::string message = std::format("Reads {} bytes instead of 8", result);
    LOG_ERROR(message);
  }
}

TimeStamp TimerQueue::nextExpiredTime() const {
  TimeStamp nextTime;
  if (!timers_.empty()) {
    nextTime = timers_.begin()->first;
  }
  return nextTime;
}

int TimerQueue::getTimeout() const {
  if (!hasTimer()) {
    return -1;
  }

  TimeStamp now  = TimeStamp::now();
  TimeStamp next = nextExpiredTime();

  if (!next.valid()) {
    return -1;
  }

  int64_t microSeconds = next.microSecondsSinceEpoch() - now.microSecondsSinceEpoch();

  int timeoutMs = static_cast<int>(microSeconds / kMillisecondPerSecond);
  return std::max(0, timeoutMs);
}

} // namespace server
