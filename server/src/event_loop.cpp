#include "include/event_loop.h"

#include "include/channel.h"
#include "include/config_manager.h"
#include "include/epoll_poller.h"
#include "include/log.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include <sys/eventfd.h>

namespace server {

namespace {
thread_local EventLoop *loopInThisThread = nullptr;
}

EventLoop::EventLoop()
    : threadId_(pthread_self())
    , poller_(new EPollPoller(this))
    , wakeupFd_(createEventfd())
    , wakeupChannel_(new Channel(this, wakeupFd_))
    , config_(*ConfigManager::getInstance().getCurrentContext().globalContext->conf) {

  if (loopInThisThread != nullptr) {
    throw std::runtime_error("Another EventLoop exists in this thread");
  }
  loopInThisThread = this;

  pthread_mutex_init(&mutex_, nullptr);

  // Initialize wake up channel
  wakeupChannel_->setReadCallback([this](const TimeStamp &) { readFromWakeupFd(); });
  wakeupChannel_->enableReading();
}

EventLoop::~EventLoop() {
  wakeupChannel_->disableAll();
  wakeupChannel_->remove();
  ::close(wakeupFd_);

  delete wakeupChannel_;
  delete poller_;

  pthread_mutex_destroy(&mutex_);
  loopInThisThread = nullptr;
}

void EventLoop::loop() {
  assertInLoopThread();

  looping_ = true;
  quit_    = false;

  while (!quit_) {
    activeChannels_.clear();
    pollReturnTime_ = poller_->poll(config_.pollTimeoutMs, &activeChannels_);

    eventHandling_           = true;
    const size_t numChannels = activeChannels_.size();
    for (size_t i = 0; i < numChannels; ++i) {
      activeChannels_[i]->handleEvent(pollReturnTime_);
    }
    eventHandling_ = false;

    doPendingFunctors();
  }

  looping_ = false;
}

void EventLoop::quit() {
  if (quit_) {
    return;
  }
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
  pthread_mutex_lock(&mutex_);
  pendingFunctors_.emplace_back(std::move(cb));
  pthread_mutex_unlock(&mutex_);

  if (!isInLoopThread() || callingPendingFunctors_) {
    writeToWakeupFd();
  }
}

void EventLoop::updateChannel(Channel *channel) {
  assertInLoopThread();
  poller_->updateChannel(channel);
}

void EventLoop::removeChannel(Channel *channel) {
  assertInLoopThread();
  poller_->removeChannel(channel);
}

void EventLoop::doPendingFunctors() {
  std::vector<Functor> functors;
  callingPendingFunctors_ = true;

  pthread_mutex_lock(&mutex_);
  functors.swap(pendingFunctors_);
  pthread_mutex_unlock(&mutex_);

  const size_t numFunctors = functors.size();
  for (size_t i = 0; i < numFunctors; ++i) {
    functors[i]();
  }
  callingPendingFunctors_ = false;
}

int EventLoop::createEventfd() {
  const int evtfd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (evtfd < 0) {
    throw std::runtime_error("Failed to create event fd: " + std::string(strerror(errno)));
  }
  return evtfd;
}

void EventLoop::writeToWakeupFd() const {
  const uint64_t one = WAKE_UP_EVENT;
  if (::write(wakeupFd_, &one, sizeof one) != sizeof one) {
    LOG_ERROR("Failed to write to wakeup fd");
  }
}

void EventLoop::readFromWakeupFd() const {
  uint64_t one = 0;
  if (::read(wakeupFd_, &one, sizeof one) != sizeof one) {
    // Only log error, don't throw in wake up path
    LOG_ERROR("Failed to read from wakeup fd");
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
