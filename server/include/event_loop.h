#pragma once

#include "include/config_defaults.h"
#include "include/time_stamp.h"
#include "include/types.h"

#include <atomic>
#include <pthread.h>
#include <vector>

namespace server {

class Channel;
class Poller;

class EventLoop {
public:
  EventLoop();
  ~EventLoop();

  EventLoop(const EventLoop &)            = delete;
  EventLoop &operator=(const EventLoop &) = delete;

  void loop();
  void quit();

  void runInLoop(Functor cb);
  void queueInLoop(Functor cb);

  void updateChannel(Channel *channel);
  void removeChannel(Channel *channel);

  [[nodiscard]] bool isInLoopThread() const noexcept { return threadId_ == pthread_self(); }
  [[nodiscard]] bool isWakeupFd(int fd) const { return fd == wakeupFd_; }
  [[nodiscard]] int getWakeupFd() const { return wakeupFd_; }
  [[nodiscard]] Poller *getPoller() const { return poller_; }

  void handleWakeup();
  void assertInLoopThread() const;

private:
  void doPendingFunctors();
  void writeToWakeupFd() const;
  void readFromWakeupFd() const;
  static int createEventfd();

  std::atomic<bool> looping_{ false };
  std::atomic<bool> quit_{ false };
  std::atomic<bool> eventHandling_{ false };
  std::atomic<bool> callingPendingFunctors_{ false };

  const pthread_t threadId_;
  Poller *poller_;
  const int wakeupFd_;
  Channel *wakeupChannel_;

  mutable pthread_mutex_t mutex_;
  std::vector<Functor> pendingFunctors_;
  ChannelList activeChannels_;
  TimeStamp pollReturnTime_;

  const GlobalConfig &config_;
  static constexpr uint64_t WAKE_UP_EVENT = 1;
};

} // namespace server
