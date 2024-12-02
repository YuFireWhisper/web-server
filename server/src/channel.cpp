#include "include/channel.h"

#include "include/epoll_poller.h"
#include "include/event_loop.h"
#include "include/log.h"
#include "include/time_stamp.h"

#include <assert.h>
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
    , index_(EPollPoller::kNew) {}

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
  loop_->updateChannel(this);
}

void Channel::remove() {
  assert(isNoneEvent());
  loop_->removeChannel(this);
}

void Channel::handleEvent(TimeStamp receiveTime) {
  eventHandling_ = true;

  if (fd_ == loop_->getWakeupFd() && revents_ & POLLIN) {
    loop_->handleWakeup();
  } else {
    if ((revents_ & POLLHUP) && !(revents_ & POLLIN)) {
      if (closeCallback_)
        closeCallback_();
    }
    if (revents_ & (POLLERR | POLLNVAL)) {
      if (errorCallback_)
        errorCallback_();
    }
    if (revents_ & (POLLIN | POLLPRI | POLLRDHUP)) {
      if (readCallback_)
        readCallback_(receiveTime);
    }
    if (revents_ & POLLOUT) {
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
