#include "include/epoll_poller.h"

#include "include/channel.h"
#include "include/event_loop.h"
#include "include/log.h"
#include "include/time_stamp.h"

namespace server {

EPollPoller::EPollPoller(EventLoop *loop)
    : Poller(loop), epollfd_(::epoll_create1(EPOLL_CLOEXEC)), events_(kInitEventListSize),
      logger_(std::make_unique<EPollLogger>()),
      eventManager_(std::make_unique<EPollEventManager>(epollfd_)) {

  if (epollfd_ < 0) {
    logger_->logEpollCreateError();
    throw std::runtime_error("EPoll creation failed");
  }
}

EPollPoller::~EPollPoller() {
  ::close(epollfd_);
}

TimeStamp EPollPoller::poll(int timeoutMs, ChannelList *activeChannels) {
  int numEvents = ::epoll_wait(epollfd_, events_.data(), events_.size(), timeoutMs);
  TimeStamp now(TimeStamp::now());

  if (numEvents > 0) {
    eventManager_->fillActiveChannels(events_, numEvents, activeChannels);
  }
  return now;
}

void EPollPoller::updateChannel(Channel *channel) {
  if (!eventManager_->hasChannel(channel)) {
    eventManager_->addChannel(channel);
  } else {
    eventManager_->modifyChannel(channel);
  }
}

void EPollPoller::removeChannel(Channel *channel) {
  if (eventManager_->hasChannel(channel)) {
    eventManager_->removeChannel(channel);
  } else {
    logger_->logChannelOperationError("remove non-existing channel");
    throw std::runtime_error("Channel not found");
  }
}

bool EPollPoller::hasChannel(Channel *channel) const {
  return eventManager_->hasChannel(channel);
}

void EPollLogger::logError(const LogMessage &message) const {
  Logger::log(LogLevel::ERROR, message, "epoll_poller.log");
}

void EPollLogger::logEpollCreateError() const {
  logError("Failed to create epoll instance");
}

void EPollLogger::logChannelOperationError(const LogMessage &operation) const {
  logError("Channel operation failed: " + operation);
}

EPollEventManager::EPollEventManager(int epollfd) : epollfd_(epollfd) {}

void EPollEventManager::addChannel(Channel *channel) {
  executeEpollControl(EPollOperation::ADD, channel);
  channels_[channel->fd()] = channel;
}

void EPollEventManager::modifyChannel(Channel *channel) {
  executeEpollControl(EPollOperation::MODIFY, channel);
}

void EPollEventManager::removeChannel(Channel *channel) {
  executeEpollControl(EPollOperation::REMOVE, channel);
  channels_.erase(channel->fd());
}

bool EPollEventManager::hasChannel(Channel *channel) const {
  return channels_.count(channel->fd()) > 0;
}

epoll_event EPollEventManager::createEpollEvent(Channel *channel) const {
  epoll_event event{};
  event.events = channel->events();
  event.data.ptr = channel;
  return event;
}

void EPollEventManager::executeEpollControl(int operation, Channel *channel) {
  auto event = createEpollEvent(channel);
  if (::epoll_ctl(epollfd_, operation, channel->fd(), &event) < 0) {
    throw std::runtime_error("EPoll control operation failed: " + getOperationName(operation));
  }
}

EPollEventManager::OperationName EPollEventManager::getOperationName(int operation) const {
  switch (operation) {
    case EPollOperation::ADD:
      return "ADD";
    case EPollOperation::MODIFY:
      return "MODIFY";
    case EPollOperation::REMOVE:
      return "REMOVE";
    default:
      return "UNKNOWN";
  }
}

void EPollEventManager::fillActiveChannels(const EPollPoller::EventList &events,
                                           int numEvents,
                                           ChannelList *activeChannels) const {

  for (int i = 0; i < numEvents; ++i) {
    auto *channel = static_cast<Channel *>(events[i].data.ptr);
    channel->set_revents(events[i].events);
    activeChannels->push_back(channel);
  }
}

} // namespace server
