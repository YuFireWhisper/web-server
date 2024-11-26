#include "include/channel.h"

#include <assert.h>

#include "include/event_loop.h"
#include "include/time_stamp.h"

namespace server {
Channel::Channel(EventLoop* loop, int fd)
    : loop_(loop),
      fd_(fd),
      events_(kNoneEvent),
      revents_(0),
      tied_(false),
      eventHandling_(false),
addedToLoop_(false) {}

Channel::~Channel() {
  assert(!eventHandling_);
  assert(!addedToLoop_);
}

void Channel::handleEvent(TimeStamp receiveTime) {
  std::shared_ptr<void> guard;
  if (tied_) {
    guard = tie_.lock();
    if (guard) {
      handleEventWithGuard(receiveTime);
    }
  } else {
    handleEventWithGuard(receiveTime);
  }
}

void Channel::handleEventWithGuard(TimeStamp receiveTime) {
  eventHandling_ = true;

  if ((revents_ & POLLERR) && errorCallback_) {
    errorCallback_();
  }

  if ((revents_ & POLLHUP) && !(revents_ & POLLIN)) {
    if (closeCallback_) closeCallback_();
  }

  if ((revents_ & (POLLIN | POLLPRI)) && readCallback_) {
    readCallback_(receiveTime);
  }

  if (revents_ & POLLOUT && writeCallback_) {
    writeCallback_();
  }

  eventHandling_ = false;
}

void Channel::tie(const std::shared_ptr<void>& obj) {
    tie_ = obj;
    tied_ = true;
}

void Channel::remove() {
    assert(isNoneEvent());
    addedToLoop_ = false;
    loop_->removeChannel(this);
}

void Channel::update() {
    addedToLoop_ = true;
    loop_->updateChannel(this);
}


}  // namespace server
