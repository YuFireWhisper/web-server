#include "include/event_loop_thread.h"

#include "include/event_loop.h"

namespace server {
EventLoopThread::EventLoopThread(ThreadInitCallback cb, std::string name)
    : loop_(nullptr)
    , exiting_(false)
    , callback_(std::move(cb))
    , name_(std::move(name)) {}

EventLoopThread::~EventLoopThread() {
  exiting_ = true;
  if (loop_ != nullptr) {
    loop_->quit();
    thread_.join();
  }
}

EventLoop *EventLoopThread::startLoop() {
  std::unique_lock<std::mutex> lock(mutex_);

  if (loop_ != nullptr) {
    return loop_;
  }

  thread_ = std::thread(&EventLoopThread::threadFunc, this);
  cond_.wait(lock, [this]() { return loop_ != nullptr; });

  return loop_;
}

void EventLoopThread::threadFunc() {
  auto loop = std::make_unique<EventLoop>();

  if (callback_) {
    callback_(loop.get());
  }

  {
    std::unique_lock<std::mutex> lock(mutex_);
    loop_ = loop.get();
    cond_.notify_one();
  }

  loop->loop();

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
