#include "include/channel.h"

#include "include/event_loop.h"
#include "include/log.h"
#include "include/time_stamp.h"
#include "include/types.h"

#include <assert.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/epoll.h>

namespace server {

Channel::Channel(EventLoop *loop, int fd)
    : loop_(loop)
    , fd_(fd)
    , events_(0)
    , revents_(0)
    , addedToLoop_(false)
    , eventHandling_(false)
    , index_(static_cast<int>(PollerState::kNew)) {}

Channel::~Channel() {
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

void Channel::update() {
  if (loop_) {
    try {
      loop_->updateChannel(this);
      addedToLoop_ = true;
    } catch (const std::exception &e) {
      Logger::log(LogLevel::ERROR, "Failed to update channel: " + std::string(e.what()));
    }
  }
}

void Channel::remove() {
  assert(isNoneEvent());
  addedToLoop_ = false;
  loop_->removeChannel(this);
}

void Channel::handleEvent(TimeStamp receiveTime) {
  eventHandling_ = true;

  if (fd_ == loop_->getWakeupFd() && revents_ & EPOLLIN) {
    loop_->handleWakeup();
  } else {
    if ((revents_ & EPOLLHUP) && !(revents_ & EPOLLIN)) {
      if (closeCallback_)
        closeCallback_();
    }
    if (revents_ & (EPOLLERR)) {
      if (errorCallback_)
        errorCallback_();
    }
    if (revents_ & (EPOLLIN | EPOLLPRI)) {
      if (readCallback_)
        readCallback_(receiveTime);
    }
    if (revents_ & EPOLLOUT) {
      if (writeCallback_)
        writeCallback_();
    }
  }

  eventHandling_ = false;
}

void Channel::handleEventWithGuard(TimeStamp receiveTime) {
  eventHandling_ = true;
  Logger::log(LogLevel::TRACE, "Channel::handleEvent() revents = " + std::to_string(revents_));
  handleEvent(receiveTime);
  eventHandling_ = false;
}

bool Channel::isInLoop() const {
  return loop_->isInLoopThread();
}

void Channel::assertInLoop() {
  loop_->assertInLoopThread();
}

} // namespace server
