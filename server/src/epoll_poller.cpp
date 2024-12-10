#include "include/epoll_poller.h"

#include "include/channel.h"

#include <climits>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

namespace server {

EPollEvent::EPollEvent() {
  std::memset(&event_, 0, sizeof(event_));
}

void EPollEvent::setEvents(uint32_t events) {
  event_.events = events;
}

void EPollEvent::setChannelPtr(void *ptr) {
  event_.data.ptr = ptr;
}

epoll_event *EPollEvent::raw() {
  return &event_;
}

EPollChannel::EPollChannel(Channel *channel)
    : channel_(channel) {}

bool EPollChannel::isNew() const {
  return channel_->index() == static_cast<int>(PollerState::kNew);
}

bool EPollChannel::isDeleted() const {
  return channel_->index() == static_cast<int>(PollerState::kDeleted);
}

bool EPollChannel::isNoneEvent() const {
  return channel_->isNoneEvent();
}

void EPollChannel::setAdded() const {
  channel_->setIndex(static_cast<int>(PollerState::kAdded));
}

void EPollChannel::setDeleted() const {
  channel_->setIndex(static_cast<int>(PollerState::kDeleted));
}

void EPollChannel::setNew() const {
  channel_->setIndex(static_cast<int>(PollerState::kNew));
}

Channel *EPollChannel::get() const {
  return channel_;
}

int EPollChannel::fd() const {
  return channel_->fd();
}

EPollOperator::EPollOperator() = default;

bool EPollOperator::add(int epollFd, const EPollChannel &channel, EPollEvent &event) {
  return control(epollFd, EPOLL_CTL_ADD, channel, event);
}

bool EPollOperator::modify(int epollFd, const EPollChannel &channel, EPollEvent &event) {
  return control(epollFd, EPOLL_CTL_MOD, channel, event);
}

bool EPollOperator::remove(int epollFd, const EPollChannel &channel, EPollEvent &event) {
  return control(epollFd, EPOLL_CTL_DEL, channel, event);
}

bool EPollOperator::control(
    int epollFd,
    int operation,
    const EPollChannel &channel,
    EPollEvent &event
) {
  return ::epoll_ctl(epollFd, operation, channel.fd(), event.raw()) >= 0;
}

EPollPoller::EPollPoller(EventLoop *loop)
    : Poller(loop)
    , events_(INITIAL_EVENT_SIZE)
    , epollFd_(::epoll_create1(EPOLL_CLOEXEC))
    , activeChannels_(nullptr) {
  if (epollFd_ < 0) {
    throw std::runtime_error("EPollPoller creation failed");
  }
}

EPollPoller::~EPollPoller() {
  cleanupChannels();
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
    handleActiveChannels(numEvents);
  }

  return TimeStamp::now();
}

void EPollPoller::handleActiveChannels(int numEvents) {
  for (int i = 0; i < numEvents; ++i) {
    auto *channel = static_cast<Channel *>(events_[i].data.ptr);
    int events = static_cast<int>(events_[i].events & INT_MAX);
    channel->setRevents(events);
    activeChannels_->push_back(channel);
  }

  if (static_cast<size_t>(numEvents) == events_.size()) {
    events_.resize(events_.size() * 2);
  }
}

void EPollPoller::updateChannel(Channel *channel) {
  assertInLoopThread();

  if (channel->fd() < 0) {
    return;
  }

  EPollChannel epollChannel(channel);
  EPollEvent event;
  event.setEvents(channel->events());
  event.setChannelPtr(channel);

  if (epollChannel.isNew() || epollChannel.isDeleted()) {
    processNewChannel(epollChannel);
  } else {
    processExistingChannel(epollChannel);
  }
}

void EPollPoller::processNewChannel(EPollChannel &epollChannel) {
  EPollEvent event;
  event.setEvents(epollChannel.get()->events());
  event.setChannelPtr(epollChannel.get());

  if (EPollOperator::add(epollFd_, epollChannel, event)) {
    channels_[epollChannel.fd()] = epollChannel.get();
    epollChannel.setAdded();
  }
}

void EPollPoller::processExistingChannel(EPollChannel &epollChannel) const {
  EPollEvent event;
  event.setEvents(epollChannel.get()->events());
  event.setChannelPtr(epollChannel.get());

  if (epollChannel.isNoneEvent()) {
    if (EPollOperator::remove(epollFd_, epollChannel, event)) {
      epollChannel.setDeleted();
    }
  } else if (epollChannel.get()->index() == static_cast<int>(PollerState::kAdded)) {
    EPollOperator::modify(epollFd_, epollChannel, event);
  }
}

void EPollPoller::removeChannel(Channel *channel) {
  assertInLoopThread();

  if (!hasChannel(channel)) {
    return;
  }

  EPollChannel epollChannel(channel);
  EPollEvent event;
  event.setEvents(channel->events());
  event.setChannelPtr(channel);

  if (channel->index() == static_cast<int>(PollerState::kAdded)) {
    EPollOperator::remove(epollFd_, epollChannel, event);
  }

  channels_.erase(channel->fd());
  epollChannel.setNew();
}

void EPollPoller::cleanupChannels() {
  for (const auto &[fd, channel] : channels_) {
    if (channel->index() == static_cast<int>(PollerState::kAdded)) {
      EPollChannel epollChannel(channel);
      EPollEvent event;
      event.setEvents(channel->events());
      event.setChannelPtr(channel);
      EPollOperator::remove(epollFd_, epollChannel, event);
    }
  }
  channels_.clear();
}
} // namespace server
