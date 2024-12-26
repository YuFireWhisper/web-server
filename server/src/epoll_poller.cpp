#include "include/epoll_poller.h"

#include "include/channel.h"
#include "include/config_manager.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

namespace server {

EPollPoller::EPollPoller(EventLoop *loop)
    : Poller(loop)
    , epollFd_(-1)
    , eventList_(nullptr)
    , eventListSize_(INITIAL_EVENT_SIZE)
    , activeChannels_(nullptr) {

  const auto &config = ConfigManager::getInstance().getCurrentContext().globalContext->conf;
  maxEventSize_      = config->maxEvents;

  eventList_ = new epoll_event[eventListSize_];
  if (!createEpollFd()) {
    delete[] eventList_;
    throw std::runtime_error("EPollPoller: epoll_create1 failed");
  }
}

EPollPoller::~EPollPoller() {
  if (epollFd_ >= 0) {
    cleanup();
    ::close(epollFd_);
  }
  delete[] eventList_;
}

TimeStamp EPollPoller::poll(int timeoutMs, ChannelList *activeChannels) {
  activeChannels_ = activeChannels;
  activeChannels_->clear();

  const int eventCount =
      ::epoll_wait(epollFd_, eventList_, static_cast<int>(eventListSize_), timeoutMs);

  if (eventCount > 0) {
    handleEvents(eventCount);
    if (static_cast<size_t>(eventCount) == eventListSize_ && eventListSize_ < maxEventSize_) {
      const size_t newSize = std::min(eventListSize_ * 2, maxEventSize_);
      if (newSize > eventListSize_) {
        auto *newList = new epoll_event[newSize];
        std::memcpy(newList, eventList_, eventListSize_ * sizeof(epoll_event));
        delete[] eventList_;
        eventList_     = newList;
        eventListSize_ = newSize;
      }
    }
  }

  return TimeStamp::now();
}

void EPollPoller::updateChannel(Channel *channel) {
  assertInLoopThread();

  const int index = channel->index();
  if (index == static_cast<int>(PollerState::kNew)
      || index == static_cast<int>(PollerState::kDeleted)) {
    addNewChannel(channel);
  } else {
    updateExistingChannel(channel);
  }
}

void EPollPoller::removeChannel(Channel *channel) {
  assertInLoopThread();

  if (hasChannel(channel)) {
    auto it = channels_.find(channel->fd());
    if (it != channels_.end()) {
      removeExistingChannel(channel);
      channels_.erase(it);
      channel->setIndex(static_cast<int>(PollerState::kNew));
    }
  }
}

void EPollPoller::handleEvents(int eventCount) {
  for (int i = 0; i < eventCount; ++i) {
    auto *channel = static_cast<Channel *>(eventList_[i].data.ptr);
    if (hasChannel(channel)) {
      channel->setRevents(static_cast<int>(eventList_[i].events));
      activeChannels_->push_back(channel);
    }
  }
}

bool EPollPoller::createEpollFd() {
  epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
  return epollFd_ >= 0;
}

void EPollPoller::updateExistingChannel(Channel *channel) {
  if (channel->isNoneEvent()) {
    removeExistingChannel(channel);
    channel->setIndex(static_cast<int>(PollerState::kDeleted));
  } else {
    updateChannelEvent(channel, EPOLL_CTL_MOD);
  }
}

void EPollPoller::addNewChannel(Channel *channel) {
  if (updateChannelEvent(channel, EPOLL_CTL_ADD)) {
    channels_[channel->fd()] = channel;
    channel->setIndex(static_cast<int>(PollerState::kAdded));
  }
}

void EPollPoller::removeExistingChannel(Channel *channel) {
  if (channel->index() == static_cast<int>(PollerState::kAdded)) {
    updateChannelEvent(channel, EPOLL_CTL_DEL);
  }
}

bool EPollPoller::updateChannelEvent(Channel *channel, int operation) const {
  epoll_event event;
  std::memset(&event, 0, sizeof(event));
  event.events   = channel->events();
  event.data.ptr = channel;

  return ::epoll_ctl(epollFd_, operation, channel->fd(), &event) >= 0;
}

void EPollPoller::cleanup() {
  for (const auto &[fd, channel] : channels_) {
    if (channel->index() == static_cast<int>(PollerState::kAdded)) {
      removeExistingChannel(channel);
    }
  }
  channels_.clear();
}

} // namespace server
