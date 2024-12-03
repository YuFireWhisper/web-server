#include "include/event_loop.h"

#include "include/channel.h"
#include "include/epoll_poller.h"
#include "include/log.h"
#include "include/poller.h"
#include "include/types.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>

#include <sys/eventfd.h>
#include <sys/types.h>

namespace server {

EventLoop::EventLoop()
    : threadId_(pthread_self())
    , poller_(new EPollPoller(this))
    , wakeupFd_(createEventfd())
    , wakeupChannel_(new Channel(this, wakeupFd_)) {
  wakeupChannel_->setReadCallback(std::bind(&EventLoop::readFromWakeupFd, this));
  wakeupChannel_->enableReading();
}

EventLoop::~EventLoop() {
  wakeupChannel_->disableAll();
  wakeupChannel_->remove();
  ::close(wakeupFd_);
}

int EventLoop::createEventfd() {
  int evtfd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

  if (evtfd < 0) {
    std::string message = "Failed to create event fd";
    logFalatMessage(message);
    throw std::runtime_error(message);
  }
  return evtfd;
}

void EventLoop::loop() {
  looping_ = true;
  quit_ = false;

  while (!quit_) {
    activeChannels_.clear();

    pollReturnTime_ = poller_->poll(kPollTimeMs, &activeChannels_);

    for (Channel *channel : activeChannels_) {
      channel->handleEvent(pollReturnTime_);
    }

    doPendingFunctors();
  }

  looping_ = false;
}

void EventLoop::quit() {
  quit_ = true;

  if (!isInLoopThread() || callingPendingFunctors_) {
    writeToWakeupFd();
  }
}

void EventLoop::writeToWakeupFd() {
  ssize_t returnBytes = ::write(wakeupFd_, &kWakeupNumber, sizeof(kWakeupNumber));
  checkReturnBytes(returnBytes);
}

void EventLoop::readFromWakeupFd() {
  uint64_t buffer = 0;
  ssize_t returnBytes = ::read(wakeupFd_, &buffer, sizeof(kWakeupNumber));
  checkReturnBytes(returnBytes);
}

void EventLoop::checkReturnBytes(ssize_t returnBytes) {
  if (returnBytes == -1) {
    std::string message = "IO operation failed: " + std::string(strerror(errno));
    logFalatMessage(message);
  } else if (returnBytes < sizeof(kWakeupNumber)) {
    std::string message =
        "Partial IO operation: " + std::to_string(returnBytes) + " bytes transmitted";
    logFalatMessage(message);
  }
}

void EventLoop::logFalatMessage(std::string message) {
  Logger::log(LogLevel::FATAL, message, "event_loop.log");
}

void EventLoop::runInLoop(Functor cb) {
  if (isInLoopThread()) {
    cb();
  } else {
    queueInLoop(cb);
  }
}

void EventLoop::queueInLoop(Functor cb) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    pendingFunctors_.push_back(std::move(cb));
  }

  if (!isInLoopThread()) {
    writeToWakeupFd();
  }
}

void EventLoop::doPendingFunctors() {
  std::vector<Functor> functors;
  callingPendingFunctors_ = true;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    functors.swap(pendingFunctors_);
  }

  for (const Functor &functor : functors) {
    functor();
  }

  callingPendingFunctors_ = false;
}

void EventLoop::updateChannel(Channel *channel) {
  poller_->updateChannel(channel);
}

void EventLoop::removeChannel(Channel *channel) {
  poller_->removeChannel(channel);
}

void EventLoop::handleWakeup() {
  readFromWakeupFd();
}

void EventLoop::assertInLoopThread() {
  if (!isInLoopThread()) {
    Logger::log(
        LogLevel::WARN,
        "Assert failed! This Thread is NOT in Loop Thread",
        "event_loop.log"
    );
    abort();
  }
}

} // namespace server
