#ifndef SERVER_EVENT_LOOP_H_
#define SERVER_EVENT_LOOP_H_

#include "include/time_stamp.h"
#include "include/types.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <vector>

namespace server {

class Channel;
class Poller;

class EventLoop {
public:
  EventLoop();
  ~EventLoop();

  void loop();
  void quit();

  void runInLoop(Functor cb);
  void queueInLoop(Functor cb);

  void updateChannel(Channel *channel);
  void removeChannel(Channel *channel);

  bool isInLoopThread() const { return pthread_equal(threadId_, pthread_self()); }
  bool isWakeupFd(int fd) const { return fd == wakeupFd_; }
  int getWakeupFd() const { return wakeupFd_; }

  void handleWakeup();
  void assertInLoopThread();

  Poller *getPoller() const { return poller_.get(); }

private:
  void doPendingFunctors();
  int createEventfd();
  void writeToWakeupFd();
  void readFromWakeupFd();

  std::atomic<bool> looping_{false};
  std::atomic<bool> quit_{false};
  std::atomic<bool> eventHandling_{false};
  std::atomic<bool> callingPendingFunctors_{false};

  const pthread_t threadId_;
  std::unique_ptr<Poller> poller_;

  int wakeupFd_;
  std::unique_ptr<Channel> wakeupChannel_;

  std::mutex mutex_;
  std::vector<Functor> pendingFunctors_;
  ChannelList activeChannels_;

  TimeStamp pollReturnTime_;

  static constexpr int kPollTimeMs = 1000;
  static constexpr uint64_t kWakeupNumber = 1;
};

} // namespace server

#endif // SERVER_EVENT_LOOP_H_
