#include "include/channel.h"

#include "include/event_loop.h"
#include "include/time_stamp.h"
#include "include/types.h"

#include <cassert>
#include <poll.h>

#include <sys/epoll.h>

namespace server {

Channel::Channel(EventLoop *loop, int fd)
    : loop_(loop)
    , fd_(fd)
    , events_(0)
    , revents_(0)
    , index_(static_cast<int>(PollerState::kNew))
    , addedToLoop_(false)
    , eventHandling_(false) {}

Channel::~Channel() {
  cleanupResources();
}

void Channel::setReadCallback(const Functor &cb) {
  readCallback_ = [cb](TimeStamp) { cb(); };
}

void Channel::cleanupResources() {
  if (addedToLoop_) {
    disableAll();
    loop_->runInLoop([this]() {
      if (addedToLoop_) {
        loop_->removeChannel(this);
        addedToLoop_ = false;
      }
    });
  }
  assert(!eventHandling_);
}

void Channel::handleEvent(TimeStamp receiveTime) {
  if (!eventHandling_) {
    eventHandling_ = true;
    processEvents(receiveTime);
    eventHandling_ = false;
  }
}

void Channel::handleEventWithGuard(TimeStamp receiveTime) {
  handleEvent(receiveTime);
}

void Channel::processEvents(TimeStamp receiveTime) {
  if (fd_ == loop_->getWakeupFd() && (revents_ & EPOLLIN) != 0) {
    loop_->handleWakeup();
    return;
  }

  if (((revents_ & EPOLLHUP) != 0) && ((revents_ & EPOLLIN) == 0)) {
    if (closeCallback_) {
      closeCallback_();
    }
  }
  if ((revents_ & EPOLLERR) != 0) {
    if (errorCallback_) {
      errorCallback_();
    }
  }
  if ((revents_ & (EPOLLIN | EPOLLPRI)) != 0) {
    if (readCallback_) {
      readCallback_(receiveTime);
    }
  }
  if ((revents_ & EPOLLOUT) != 0) {
    if (writeCallback_) {
      writeCallback_();
    }
  }
}

void Channel::updateEventStatus(int events) {
  events_ = events;
  notifyLoopOfUpdate();
}

void Channel::notifyLoopOfUpdate() {
  if (loop_ != nullptr) {
    loop_->updateChannel(this);
    addedToLoop_ = true;
  }
}

void Channel::remove() {
  assert(isNoneEvent());
  addedToLoop_ = false;
  loop_->removeChannel(this);
}

bool Channel::isInLoop() const {
  return loop_->isInLoopThread();
}

void Channel::assertInLoop() {
  loop_->assertInLoopThread();
}

} // namespace server
