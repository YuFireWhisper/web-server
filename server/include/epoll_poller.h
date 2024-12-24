#pragma once

#include "include/poller.h"
#include "include/time_stamp.h"
#include "include/types.h"

#include <sys/epoll.h>

namespace server {

class Channel;

class EPollPoller final : public Poller {
public:
  explicit EPollPoller(EventLoop *loop);
  ~EPollPoller() override;

  EPollPoller(const EPollPoller &)            = delete;
  EPollPoller &operator=(const EPollPoller &) = delete;

  TimeStamp poll(int timeoutMs, ChannelList *activeChannels) override;
  void updateChannel(Channel *channel) override;
  void removeChannel(Channel *channel) override;

private:
  void handleEvents(int eventCount);
  bool createEpollFd();
  void updateExistingChannel(Channel *channel);
  void addNewChannel(Channel *channel);
  void removeExistingChannel(Channel *channel);

  bool updateChannelEvent(Channel *channel, int operation) const;
  void cleanup();

  static constexpr size_t INITIAL_EVENT_SIZE = 16;

  int epollFd_;
  epoll_event *eventList_;
  size_t eventListSize_;
  size_t maxEventSize_;
  ChannelList *activeChannels_;
};

} // namespace server
