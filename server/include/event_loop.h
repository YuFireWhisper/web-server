#include "include/time_stamp.h"
#include "include/types.h"

#include <atomic>
#include <memory>
#include <pthread.h>
#include <unistd.h>

#include <sys/types.h>

namespace server {

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

private:
  void doPendingFunctors();
  int createEventfd();

  void writeToWakeupFd();
  void readFromWakeupFd();
  void checkReturnBytes(ssize_t returnBytes);

  void logFalatMessage(std::string message);

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

private:
  static constexpr int kPollTimeMs = 1000;
  static constexpr uint64_t kWakeupNumber = 1;
};
} // namespace server
