#include "include/event_loop_thread_pool.h"

#include "include/event_loop.h"
#include "include/event_loop_thread.h"
#include "include/log.h"

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>

namespace server {
void checkBaseLoop(EventLoop *baseLoop);

EventLoopThreadPool::EventLoopThreadPool(EventLoop *baseLoop, std::string nameArg)
    : baseLoop_(baseLoop)
    , name_(std::move(nameArg))
    , started_(false)
    , numThreads_(0)
    , next_(0) {
  checkBaseLoop(baseLoop);
}

void checkBaseLoop(EventLoop *baseLoop) {
  if (baseLoop == nullptr) {
    std::string message = "BaseLoop cannot be null";
    Logger::log(LogLevel::FATAL, message);
    throw std::invalid_argument(message);
  }
}

void EventLoopThreadPool::start(const ThreadInitCallback &cb) {
  started_ = true;

  for (int i = 0; i < numThreads_; ++i) {
    const size_t kMoreSize = 32;
    size_t bufSize = name_.size() + kMoreSize;
    std::vector<char> buf(bufSize);
    snprintf(buf.data(), buf.size(), "%s%d", name_.c_str(), i);

    auto thread = std::make_unique<EventLoopThread>(cb, std::string(buf.data()));

    EventLoop *loop = thread.get()->startLoop();

    loops_.push_back(loop);
    threads_.push_back(std::move(thread));
  }

  if (cb) {
    cb(baseLoop_);
  }
}

EventLoop *EventLoopThreadPool::getNextLoop() {
  EventLoop *loop = baseLoop_;

  if (!loops_.empty()) {
    loop = loops_[next_];
    next_ = (next_ + 1) % static_cast<int>(loops_.size());
  }

  return loop;
}

EventLoop *EventLoopThreadPool::getLoopForHash(size_t hashCode) {
  EventLoop *loop = baseLoop_;

  if (!loops_.empty()) {
    loop = loops_[hashCode % loops_.size()];
  }

  return loop;
}

std::vector<EventLoop *> EventLoopThreadPool::getAllLoops() {
  if (!started_) {
    return {};
  }

  if (loops_.empty()) {
    return std::vector<EventLoop *>{baseLoop_};
  }

  return loops_;
}

} // namespace server
