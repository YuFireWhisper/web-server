#include "include/event_loop_thread.h"

#include "include/event_loop.h"

namespace server {
EventLoopThread::EventLoopThread(ThreadInitCallback cb, std::string name)
    : loop_(nullptr)
    , callback_(std::move(cb))
    , name_(std::move(name)) {}

EventLoopThread::~EventLoopThread() {
  stop();
}

EventLoop *EventLoopThread::startLoop() {
  std::unique_lock<std::mutex> lock(mutex_);

  if (loop_ != nullptr || thread_.joinable()) {
    return nullptr;
  }

  thread_ = std::thread(&EventLoopThread::threadFunc, this);
  cond_.wait(lock, [this]() { return loop_ != nullptr; });

  return loop_;
}

void EventLoopThread::stop() {
  if (loop_ == nullptr) {
    return;
  }

  EventLoop *loop = nullptr;
  {
    std::unique_lock<std::mutex> lock(mutex_);
    if (loop_ == nullptr || !thread_.joinable()) {
      return;
    }
    loop = loop_;
    loop->quit();
  }

  if (thread_.joinable()) {
    thread_.join();
  }
}

void EventLoopThread::threadFunc() {
  EventLoop loop;

  if (callback_) {
    callback_(&loop);
  }

  {
    std::unique_lock<std::mutex> lock(mutex_);
    loop_ = &loop;
    cond_.notify_one();
  }

  loop.loop();

  {
    std::unique_lock<std::mutex> lock(mutex_);
    loop_ = nullptr;
  }
}

bool EventLoopThread::isRunning() {
  std::unique_lock<std::mutex> lock(mutex_);
  return loop_ != nullptr;
}

} // namespace server
