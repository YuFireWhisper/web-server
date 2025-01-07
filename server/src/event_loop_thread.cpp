#include "include/event_loop_thread.h"

#include "include/event_loop.h"

namespace server {
EventLoopThread::EventLoopThread(ThreadInitCallback cb, std::string name)
    : loop_(nullptr)
    , exiting_(false)
    , callback_(std::move(cb))
    , name_(std::move(name)) {}

EventLoopThread::~EventLoopThread() {
  stop();
}

EventLoop *EventLoopThread::startLoop() {
  std::unique_lock<std::mutex> lock(mutex_);

  if (loop_ != nullptr) {
    return loop_.get();
  }

  thread_ = std::thread(&EventLoopThread::threadFunc, this);
  cond_.wait(lock, [this]() { return loop_ != nullptr; });

  return loop_.get();
}

void EventLoopThread::threadFunc() {
  auto loop = std::make_shared<EventLoop>();
  {
    std::unique_lock<std::mutex> lock(mutex_);
    loop_ = loop;
    cond_.notify_one();
  }

  loop->loop();

  {
    std::unique_lock<std::mutex> lock(mutex_);
    loop_.reset();
  }
}

bool EventLoopThread::isRunning() {
  std::unique_lock<std::mutex> lock(mutex_);
  return loop_ != nullptr;
}

void EventLoopThread::stop() {
  std::shared_ptr<EventLoop> loop;
  {
    std::unique_lock<std::mutex> lock(mutex_);
    loop = loop_;
  }

  if (loop) {
    loop->quit();
  }

  if (thread_.joinable()) {
    exiting_ = true;
    thread_.join();
  }
}

} // namespace server
