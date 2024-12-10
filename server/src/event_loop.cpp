#include "include/event_loop.h"

#include "include/channel.h"
#include "include/epoll_poller.h"

#include <stdexcept>
#include <unistd.h>

#include <sys/eventfd.h>

namespace server {

EventLoop::EventLoop()
    : threadId_(pthread_self())
    , poller_(new EPollPoller(this))
    , wakeupFd_(createEventfd())
    , wakeupChannel_(new Channel(this, wakeupFd_)) {
  wakeupChannel_->setReadCallback([this](const TimeStamp &) { readFromWakeupFd(); });
  wakeupChannel_->enableReading();
}

EventLoop::~EventLoop() {
  wakeupChannel_->disableAll();
  wakeupChannel_->remove();
  ::close(wakeupFd_);
}

void EventLoop::loop() {
  looping_ = true;
  quit_ = false;

  while (!quit_) {
    activeChannels_.clear();
    pollReturnTime_ = poller_->poll(kPollTimeMs, &activeChannels_);

    eventHandling_ = true;
    for (Channel *channel : activeChannels_) {
      channel->handleEvent(pollReturnTime_);
    }
    eventHandling_ = false;

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

void EventLoop::runInLoop(Functor cb) {
  if (isInLoopThread()) {
    cb();
  } else {
    queueInLoop(std::move(cb));
  }
}

void EventLoop::queueInLoop(Functor cb) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    pendingFunctors_.push_back(std::move(cb));
  }

  if (!isInLoopThread() || callingPendingFunctors_) {
    writeToWakeupFd();
  }
}

void EventLoop::updateChannel(Channel *channel) {
  poller_->updateChannel(channel);
}

void EventLoop::removeChannel(Channel *channel) {
  poller_->removeChannel(channel);
}

void EventLoop::doPendingFunctors() {
  std::vector<Functor> functors;
  callingPendingFunctors_ = true;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    functors.swap(pendingFunctors_);
  }

  for (const auto &functor : functors) {
    functor();
  }

  callingPendingFunctors_ = false;
}

int EventLoop::createEventfd() {
  int evtfd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (evtfd < 0) {
    throw std::runtime_error("Failed to create event fd");
  }
  return evtfd;
}

void EventLoop::writeToWakeupFd() const {
  uint64_t one = kWakeupNumber;
  if (::write(wakeupFd_, &one, sizeof one) != sizeof one) {
    throw std::runtime_error("Failed to write to wakeup fd");
  }
}

void EventLoop::readFromWakeupFd() const {
  uint64_t one = 0;
  if (::read(wakeupFd_, &one, sizeof one) != sizeof one) {
    throw std::runtime_error("Failed to read from wakeup fd");
  }
}

void EventLoop::handleWakeup() {
  readFromWakeupFd();
}

void EventLoop::assertInLoopThread() const {
  if (!isInLoopThread()) {
    throw std::runtime_error("EventLoop was created in a different thread");
  }
}

} // namespace server
