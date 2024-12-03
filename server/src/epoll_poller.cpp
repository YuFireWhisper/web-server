#include "include/epoll_poller.h"

#include "include/channel.h"

#include <cerrno>
#include <stdexcept>
#include <unistd.h>

namespace server {

EPollPoller::EPollPoller(EventLoop *loop)
    : Poller(loop)
    , epollFd_(::epoll_create1(EPOLL_CLOEXEC))
    , events_(INITIAL_EVENT_SIZE)
    , activeChannels_(nullptr)
    , currentChannel_(nullptr) {
  if (epollFd_ < 0) {
    throw std::runtime_error("EPollPoller creation failed");
  }
}

EPollPoller::~EPollPoller() {
  for (const auto &[fd, channel] : channels_) {
    if (channel->index() == static_cast<int>(PollerState::kAdded)) {
      deleteChannel(channel);
    }
  }
  ::close(epollFd_);
}

TimeStamp EPollPoller::poll(int timeoutMs, ChannelList *activeChannels) {
  activeChannels_ = activeChannels;
  return doPoll(timeoutMs);
}

TimeStamp EPollPoller::doPoll(int timeoutMs) {
  int numEvents =
      ::epoll_wait(epollFd_, events_.data(), static_cast<int>(events_.size()), timeoutMs);

  if (numEvents > 0) {
    for (int i = 0; i < numEvents; ++i) {
      auto channel = static_cast<Channel *>(events_[i].data.ptr);
      channel->set_revents(events_[i].events);
      activeChannels_->push_back(channel);
    }
    resizeEventsIfNeeded();
  } else if (numEvents < 0 && errno != EINTR) {
    errno = 0;
  }

  return TimeStamp::now();
}

void EPollPoller::resizeEventsIfNeeded() {
  if (static_cast<size_t>(events_.size()) == events_.size()) {
    events_.resize(events_.size() * 2);
  }
}

void EPollPoller::updateChannel(Channel *channel) {
  assertInLoopThread();

  const int fd = channel->fd();
  const int index = channel->index();

  if (fd < 0)
    return;

  currentChannel_ = channel;

  if (isChannelNew(index) || isChannelDeleted(index)) {
    if (tryEpollCtl(EPOLL_CTL_ADD, fd)) {
      channels_[fd] = channel;
      channel->set_index(static_cast<int>(PollerState::kAdded));
    }
  } else if (isNoneEventChannel(channel)) {
    if (tryEpollCtl(EPOLL_CTL_DEL, fd)) {
      channel->set_index(static_cast<int>(PollerState::kDeleted));
    }
  } else if (channel->index() == static_cast<int>(PollerState::kAdded)) {
    tryEpollCtl(EPOLL_CTL_MOD, fd);
  }
}

void EPollPoller::removeChannel(Channel *channel) {
  assertInLoopThread();

  if (!hasChannel(channel))
    return;

  if (channel->index() == static_cast<int>(PollerState::kAdded)) {
    deleteChannel(channel);
  }

  channels_.erase(channel->fd());
  channel->set_index(static_cast<int>(PollerState::kNew));
}

void EPollPoller::addChannel(Channel *channel) {
  channels_[channel->fd()] = channel;
  channel->set_index(static_cast<int>(PollerState::kAdded));
  setEventData(channel);
  updateChannelEvents(EPOLL_CTL_ADD);
}

void EPollPoller::modifyChannel(Channel *channel) {
  setEventData(channel);
  updateChannelEvents(EPOLL_CTL_MOD);
}

void EPollPoller::deleteChannel(Channel *channel) {
  setEventData(channel);
  updateChannelEvents(EPOLL_CTL_DEL);
  channel->set_index(static_cast<int>(PollerState::kDeleted));
}

void EPollPoller::setEventData(Channel *channel) {
  currentEvent_ = {0};
  currentEvent_.events = channel->events();
  currentEvent_.data.ptr = channel;
}

void EPollPoller::updateChannelEvents(int operation) {
  tryEpollCtl(operation, currentChannel_->fd());
}

bool EPollPoller::tryEpollCtl(int operation, int fd) {
  setEventData(currentChannel_);
  return ::epoll_ctl(epollFd_, operation, fd, &currentEvent_) >= 0;
}

bool EPollPoller::isChannelNew(int index) const {
  return index == static_cast<int>(PollerState::kNew);
}

bool EPollPoller::isChannelDeleted(int index) const {
  return index == static_cast<int>(PollerState::kDeleted);
}

bool EPollPoller::isNoneEventChannel(Channel *channel) const {
  return channel->isNoneEvent();
}

} // namespace server
