#include "include/timer_queue.h"

#include "include/channel.h"
#include "include/event_loop.h"
#include "include/log.h"
#include "include/time_stamp.h"
#include "include/timer.h"
#include "include/timer_id.h"

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
    : loop_(loop)
    , sequence_(0)
    , timerfd_(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)) {
  if (timerfd_ < 0) {
    Logger::log(LogLevel::FATAL, "TimerQueue::TimerQueue timerfd create error");
    abort();
  }
  timerfdChannel_ = std::make_unique<Channel>(loop, timerfd_);
  timerfdChannel_->setReadCallback(std::bind(&TimerQueue::handleRead, this));
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
  Timer *timer = new Timer(std::move(cb), when, interval);
  TimerId id(timer, sequence_++);
  loop_->runInLoop(std::bind(&TimerQueue::addTimerInLoop, this, timer));
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
  TimeStamp when = timer->expiration();
  TimerList::iterator it = timers_.begin();

  if (it == timers_.end() || when < it->first) {
    earliestChanged = true;
  }

  std::pair<TimerList::iterator, bool> result = timers_.insert(TimerEntry(when, timer));

  return earliestChanged;
}

void TimerQueue::resetTimerfd() {
  loop_->assertInLoopThread();

  TimeStamp earliestTime;
  if (!timers_.empty()) {
    earliestTime = timers_.begin()->first;
  }

  if (earliestTime.valid()) {
    struct timespec howlong;
    TimeStamp now = TimeStamp::now();
    int64_t microsendconds = earliestTime.microSecondsSinceEpoch() - now.microSecondsSinceEpoch();
    if (microsendconds < 100) {
      microsendconds = 100;
    }

    struct itimerspec newValue;
    bzero(&newValue, sizeof newValue);

    newValue.it_value.tv_sec = static_cast<time_t>(microsendconds / MicroSecondsPerSecond);
    newValue.it_value.tv_nsec = static_cast<long>((microsendconds % MicroSecondsPerSecond) * 1000);

    int ret = ::timerfd_settime(timerfd_, 0, &newValue, nullptr);
    if (ret < 0) {
      int saveErrno = errno;
      std::string errorMessage =
          std::format("Failed to set timer: {} (errno={})", strerror(saveErrno), saveErrno);
      Logger::log(LogLevel::ERROR, errorMessage, "timer_queue.log");
    }
  }
}

void TimerQueue::handleRead() {
  loop_->assertInLoopThread();

  readTimerfd();

  TimeStamp now(TimeStamp::now());
  std::vector<TimerEntry> expired = getExpired();
  for (const TimerEntry &it : expired) {
    it.second->run();

    if (it.second->repeat()) {
      it.second->restart();
      insert(it.second);
    } else {
      delete it.second;
    }

    if (!timers_.empty()) {
      resetTimerfd();
    }
  }
}

std::vector<TimerEntry> TimerQueue::getExpired() {
  TimeStamp now = TimeStamp::now();
  TimerEntry sentry(now, nullptr);
  TimerList::iterator end = timers_.lower_bound(sentry);
  std::vector<TimerEntry> expried(timers_.begin(), end);
  timers_.erase(timers_.begin(), end);
  return expried;
}

void TimerQueue::readTimerfd() {
  uint64_t howmany;

  ssize_t n = ::read(timerfd_, &howmany, sizeof howmany);

  if (n != sizeof(howmany)) {
    std::string errorMessage = std::format("Reads {} bytes instead of 8", n);
    Logger::log(LogLevel::ERROR, errorMessage);
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

  TimeStamp now = TimeStamp::now();
  TimeStamp next = nextExpiredTime();

  if (next.valid()) {
    return -1;
  }

  int64_t microSeconds = next.microSecondsSinceEpoch() - now.microSecondsSinceEpoch();

  int timeoutMs = static_cast<int>(microSeconds / 1000);
  return std::max(0, timeoutMs);
}

} // namespace server
