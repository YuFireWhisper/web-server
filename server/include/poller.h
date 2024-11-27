#pragma once

#include <map>
#include <vector>

namespace server {
class Channel;
class EventLoop;
class TimeStamp;

class Poller {
public:
  typedef std::vector<Channel *> ChannelList;

  Poller(EventLoop *loop);
  virtual ~Poller() = default;

  virtual TimeStamp poll(int timeoutMs, ChannelList *activeChannels) = 0;
  virtual void updateChannel(Channel *channel) = 0;
  virtual void removeChannel(Channel *channel) = 0;
  virtual bool hasChannel(Channel *channel) const = 0;
  virtual Poller *newDefaultPoller(EventLoop *loop) = 0;

protected:
  typedef std::map<int, Channel *> ChannelMap;
  ChannelMap channels_;

private:
  EventLoop *ownerLoop_;
};
} // namespace server
