#include "include/channel.h"

#include "include/event_loop.h"
#include "include/time_stamp.h"

#include <sys/epoll.h>

namespace server {

Channel::Channel(EventLoop *loop, int fd)
    : loop_(loop)
    , fd_(fd)
    , events_(kNoneEvent)
    , revents_(0)
    , index_(-1)
    , addedToLoop_(false)
    , eventHandling_(false) {}

Channel::~Channel() {
  cleanupResources();
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
  const int events = revents_;

  if (((events & EPOLLHUP) != 0U) && ((events & EPOLLIN) == 0U)) {
    if (closeCallback_) {
      closeCallback_();
    }
    return;
  }

  if ((events & EPOLLERR) != 0) {
    if (errorCallback_) {
      errorCallback_();
    }
    return;
  }

  if ((events & (EPOLLIN | EPOLLPRI)) != 0) {
    if (fd_ == loop_->getWakeupFd()) {
      loop_->handleWakeup();
    } else if (readCallback_) {
      readCallback_(receiveTime);
    }
  }

  if ((events & EPOLLOUT) != 0) {
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
  if (isNoneEvent()) {
    addedToLoop_ = false;
    loop_->removeChannel(this);
  }
}

bool Channel::isInLoop() const {
  return loop_->isInLoopThread();
}

void Channel::assertInLoop() {
  loop_->assertInLoopThread();
}

} // namespace server
