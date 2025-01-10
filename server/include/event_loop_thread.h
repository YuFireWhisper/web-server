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
  EventLoopThread(ThreadInitCallback cb = ThreadInitCallback(), std::string name = std::string());
  ~EventLoopThread();

  EventLoopThread(const EventLoopThread &)            = delete;
  EventLoopThread &operator=(const EventLoopThread &) = delete;

  EventLoop *startLoop();
  void stop();

  bool isRunning();

private:
  void threadFunc();

  EventLoop *loop_;
  std::thread thread_;
  std::mutex mutex_;
  std::condition_variable cond_;
  ThreadInitCallback callback_;
  std::string name_;
};
} // namespace server
