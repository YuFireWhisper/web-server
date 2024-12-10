#pragma once

#include "include/types.h"

#include <memory>
#include <vector>

namespace server {
class EventLoop;
class EventLoopThread;

class EventLoopThreadPool {
public:
  EventLoopThreadPool(EventLoop *baseLoop, const std::string &nameArg = std::string());
  ~EventLoopThreadPool() = default;

  EventLoopThreadPool(const EventLoopThreadPool &) = delete;
  EventLoopThreadPool &operator=(const EventLoopThreadPool &) = delete;

  void setThreadNum(int numThreads) { numThreads_ = numThreads; }
  void start(const ThreadInitCallback &cb = ThreadInitCallback());

  EventLoop *getNextLoop();
  EventLoop *getLoopForHash(size_t hashCode);
  std::vector<EventLoop *> getAllLoops();

  bool isStarted() const { return started_; }
  const std::string &name() const { return name_; }

private:
  EventLoop *baseLoop_;
  std::string name_;
  bool started_;
  int numThreads_;
  int next_;
  std::vector<std::unique_ptr<EventLoopThread>> threads_;
  std::vector<EventLoop *> loops_;
};
} // namespace server
