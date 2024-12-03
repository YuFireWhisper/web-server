#pragma once

#include "time_stamp.h"
#include "poller.h"
#include "types.h"

#include <vector>
#include <sys/epoll.h>

namespace server {

class EPollPoller : public Poller {
public:
  EPollPoller(EventLoop* loop);
  ~EPollPoller() override;

  TimeStamp poll(int timeoutMs, ChannelList* activeChannels) override;
  void updateChannel(Channel* channel) override;
  void removeChannel(Channel* channel) override;

private:
  static constexpr int INITIAL_EVENT_SIZE = 16;
  
  using EventList = std::vector<struct epoll_event>;
  
  // Poll operations
  TimeStamp doPoll(int timeoutMs);
  void handlePollResult();
  void fillActiveChannels();
  void resizeEventsIfNeeded();

  // Channel operations
  void addChannel(Channel* channel);
  void modifyChannel(Channel* channel);
  void deleteChannel(Channel* channel);
  void updateChannelEvents(int operation);
  
  // Event handling
  void setEventData(Channel* channel);
  bool tryEpollCtl(int operation, int fd);
  
  // State checks
  bool isChannelNew(int index) const;
  bool isChannelDeleted(int index) const;
  bool isNoneEventChannel(Channel* channel) const;
  
  int epollFd_;
  EventList events_;
  ChannelList* activeChannels_;
  
  Channel* currentChannel_;
  struct epoll_event currentEvent_;
};

} // namespace server
