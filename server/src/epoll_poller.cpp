#include "include/epoll_poller.h"

#include "include/channel.h"
#include "include/event_loop.h"
#include "include/log.h"
#include "include/time_stamp.h"

namespace server {

EPollPoller::EPollPoller(EventLoop* loop)
    : Poller(loop),
      epollfd_(::epoll_create1(EPOLL_CLOEXEC)),
      events_(kInitEventListSize) {
  if (epollfd_ < 0) {
    Logger::log(LogLevel::ERROR,
                "EPollPoller::EPollPoller create epollfd failed",
                "epoll_poller.log");
    throw std::runtime_error("EPollPoller::EPollPoller create epollfd failed");
  }
}

EPollPoller::~EPollPoller() { ::close(epollfd_); }

TimeStamp EPollPoller::poll(int timeoutMs, ChannelList* activeChannels) {
  int numEvents =
      ::epoll_wait(epollfd_, events_.data(), events_.size(), timeoutMs);
  int savedErrno = errno;
  TimeStamp now(TimeStamp::now());

  if (numEvents > 0) {
    Logger::log(
        LogLevel::TRACE,
        "EPollPoller::poll() " + std::to_string(numEvents) + " events happened",
        "epoll_poller.log");
    fillActiveChannels(numEvents, activeChannels);
    if (static_cast<size_t>(numEvents) == events_.size()) {
      events_.resize(events_.size() * 2);
    }
  } else if (numEvents == 0) {
    Logger::log(LogLevel::TRACE, "EPollPoller::poll() nothing happened",
                "epoll_poller.log");
  } else {
    if (savedErrno != EINTR) {
      errno = savedErrno;
      Logger::log(LogLevel::ERROR, "EPollPoller::poll() error happened",
                  "epoll_poller.log");
    }
  }

  return now;
}

void EPollPoller::updateChannel(Channel* channel) {
  const int fd = channel->fd();
  const int events = channel->events();

  if (!hasChannel(channel)) {
    struct epoll_event event;
    event.events = events;
    event.data.ptr = channel;
    if (::epoll_ctl(epollfd_, EPOLL_CTL_ADD, fd, &event) < 0) {
      Logger::log(LogLevel::ERROR,
                  "EPollPoller::updateChannel() add channel failed",
                  "epoll_poller.log");
      throw std::runtime_error(
          "EPollPoller::updateChannel() add channel failed");
    }
    channels_[fd] = channel;
  } else {
    struct epoll_event event;
    event.events = events;
    event.data.ptr = channel;
    if (::epoll_ctl(epollfd_, EPOLL_CTL_MOD, fd, &event) < 0) {
      Logger::log(LogLevel::ERROR,
                  "EPollPoller::updateChannel() mod channel failed",
                  "epoll_poller.log");
      throw std::runtime_error(
          "EPollPoller::updateChannel() mod channel failed");
    }
  }
}

void EPollPoller::removeChannel(Channel* channel) {
  const int fd = channel->fd();
  const int events = channel->events();

  if (hasChannel(channel)) {
    struct epoll_event event;
    event.events = events;
    event.data.ptr = channel;
    if (::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, &event) < 0) {
      Logger::log(LogLevel::ERROR,
                  "EPollPoller::removeChannel() del channel failed",
                  "epoll_poller.log");
      throw std::runtime_error(
          "EPollPoller::removeChannel() del channel failed");
    }
    channels_.erase(fd);
  } else {
    Logger::log(LogLevel::ERROR,
                "EPollPoller::removeChannel() channel not found",
                "epoll_poller.log");
    throw std::runtime_error("EPollPoller::removeChannel() channel not found");
  }
}

bool EPollPoller::hasChannel(Channel* channel) const {
  return channels_.count(channel->fd());
}

void EPollPoller::fillActiveChannels(int numEvents,
                                     ChannelList* activeChannels) const {
  for (int i = 0; i < numEvents; ++i) {
    Channel* channel = static_cast<Channel*>(events_[i].data.ptr);
    channel->set_revents(events_[i].events);
    activeChannels->push_back(channel);
  }
}

const char* EPollPoller::operationToString(int op) {
  switch (op) {
    case EPOLL_CTL_ADD:
      return "ADD";
    case EPOLL_CTL_MOD:
      return "MOD";
    case EPOLL_CTL_DEL:
      return "DEL";
    default:
      return "UNKNOWN";
  }
}

void EPollPoller::update(int operation, Channel* channel) {
  struct epoll_event event;
  event.events = channel->events();
  event.data.ptr = channel;
  if (::epoll_ctl(epollfd_, operation, channel->fd(), &event) < 0) {
    Logger::log(LogLevel::ERROR,
                std::string("EPollPoller::update() ") +
                    operationToString(operation) + " channel failed",
                "epoll_poller.log");
    throw std::runtime_error(std::string("EPollPoller::update() ") +
                             operationToString(operation) + " channel failed");
  }
}

}  // namespace server
