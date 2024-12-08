#pragma once

#include "include/types.h"

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

namespace server {

class EventLoop;

class EventLoopThread {
public:
  EventLoopThread(
      const ThreadInitCallback &cb = ThreadInitCallback(),
      const std::string &name = std::string()
  );
  ~EventLoopThread();

  EventLoopThread(const EventLoopThread &) = delete;
  EventLoopThread &operator=(const EventLoopThread &) = delete;

  EventLoop *startLoop();

  bool isRunning();

private:
  void threadFunc();

  EventLoop *loop_;
  std::atomic<bool> exiting_;
  std::thread thread_;
  std::mutex mutex_;
  std::condition_variable cond_;
  ThreadInitCallback callback_;
  std::string name_;
};
} // namespace server