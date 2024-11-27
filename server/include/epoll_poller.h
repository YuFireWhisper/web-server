#pragma once

#include "include/poller.h"

#include <sys/epoll.h>

namespace server {

class EventLoop;

class EPollPoller : public Poller {
public:
  typedef std::vector<struct epoll_event> EventList;
  EPollPoller(EventLoop *loop);
  ~EPollPoller() override;

  TimeStamp poll(int timeoutMs, ChannelList *activeChannels) override;
  void updateChannel(Channel *channel) override;
  void removeChannel(Channel *channel) override;
  bool hasChannel(Channel *channel) const override;

private:
  static const int kInitEventListSize = 16;
  static const char *operationToString(int op);

  void fillActiveChannels(int numEvents, ChannelList *activeChannels) const;
  void update(int operation, Channel *channel);

  int epollfd_;
  EventList events_;
};

} // namespace server
