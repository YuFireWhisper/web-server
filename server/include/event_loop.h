#pragma once

#include <sys/types.h>
#include <memory>
#include <functional>
#include <mutex>
#include <vector>

namespace server {
class Channel;
class Poller;

class EventLoop {
private:
  bool looping_;
  bool quit_;
  bool eventHandling_;
  bool callingPendingFunctors_;
  const pid_t threadId_;
  std::unique_ptr<Poller> poller_;

  int wakeupFd_;
  std::unique_ptr<Channel> wakeupChannel_;

  std::mutex mutex_;
  std::vector<std::function<void>> pendingFunctors;
public:
  EventLoop();
  ~EventLoop();

  void loop();
  void quit();

  void runInLoop();
  bool isInLoopThread() const;

  void updateChannel(Channel* channel);
  void removeChannel(Channel* channel);
  bool hasChannel(Channel* channel);

private:
  void handleRead();
};
}
