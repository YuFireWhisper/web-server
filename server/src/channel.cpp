#include "include/channel.h"

#include "include/event_loop.h"
#include "include/log.h"
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
  LOG_DEBUG("Channel fd=" + std::to_string(fd_) + " handleEvent with revents=" + std::to_string(revents_));
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
  LOG_DEBUG("Channel fd=" + std::to_string(fd_) + " 處理事件");

  if (((revents_ & EPOLLHUP) != 0u) && !(revents_ & EPOLLIN)) {
    if (closeCallback_)
      closeCallback_();
    return;
  }

  if (revents_ & EPOLLERR) {
    if (errorCallback_)
      errorCallback_();
    return;
  }

  // 再處理讀寫事件
  if (revents_ & EPOLLIN) {
        if (fd_ == loop_->getWakeupFd()) {
            LOG_DEBUG("處理喚醒事件");
            loop_->handleWakeup();
        } else if (readCallback_) {
            LOG_DEBUG("Channel fd=" + std::to_string(fd_) + " 執行讀取回調");
            readCallback_(receiveTime);
        }
    }

  if (revents_ & EPOLLOUT) {
    if (writeCallback_)
      writeCallback_();
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
