#pragma once

#include "include/types.h"

namespace server {

class Channel;
class EventLoop;

class Poller {
public:
  explicit Poller(EventLoop *loop);
  virtual ~Poller() = default;

  Poller(const Poller &) = delete;
  Poller &operator=(const Poller &) = delete;

  virtual TimeStamp poll(int timeoutMs, ChannelList *activeChannels) = 0;
  virtual void updateChannel(Channel *channel) = 0;
  virtual void removeChannel(Channel *channel) = 0;
  bool hasChannel(Channel *channel) const;

  static Poller *newDefaultPoller(EventLoop *loop);

  void assertInLoopThread() const;

  const ChannelMap &getChannels() const { return channels_; }

protected:
  ChannelMap channels_;

private:
  EventLoop *ownerLoop_;
};

} // namespace server
