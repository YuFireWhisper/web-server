#pragma once

#include "poller.h"
#include "time_stamp.h"
#include "types.h"

#include <vector>

#include <sys/epoll.h>

namespace server {

class EPollEvent {
public:
  explicit EPollEvent();

  void setEvents(uint32_t events);
  void setChannelPtr(void *ptr);
  epoll_event *raw();

private:
  epoll_event event_;
};

class EPollChannel {
public:
  explicit EPollChannel(Channel *channel);

  bool isNew() const;
  bool isDeleted() const;
  bool isNoneEvent() const;
  void setAdded() const;
  void setDeleted() const;
  void setNew() const;

  Channel *get() const;
  int fd() const;

private:
  Channel *channel_;
};

class EPollOperator {
public:
  explicit EPollOperator();

  bool add(int epollFd, const EPollChannel &channel, EPollEvent &event);
  bool modify(int epollFd, const EPollChannel &channel, EPollEvent &event);
  bool remove(int epollFd, const EPollChannel &channel, EPollEvent &event);

private:
  bool control(int epollFd, int operation, const EPollChannel &channel, EPollEvent &event);
};

class EPollPoller : public Poller {
public:
  explicit EPollPoller(EventLoop *loop);
  ~EPollPoller() override;

  TimeStamp poll(int timeoutMs, ChannelList *activeChannels) override;
  void updateChannel(Channel *channel) override;
  void removeChannel(Channel *channel) override;

private:
  void processNewChannel(EPollChannel &epollChannel);
  void processExistingChannel(EPollChannel &epollChannel);
  void cleanupChannels();
  TimeStamp doPoll(int timeoutMs);
  void handleActiveChannels(int numEvents);

  static constexpr int INITIAL_EVENT_SIZE = 16;

  std::vector<epoll_event> events_;
  int epollFd_;
  EPollOperator operator_;
  ChannelList *activeChannels_;
};

} // namespace server
