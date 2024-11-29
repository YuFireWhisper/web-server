#pragma once

#include "include/poller.h"
#include "include/types.h"

#include <memory>
#include <vector>

#include <sys/epoll.h>

namespace server {

class EventLoop;
class Channel;
class EPollLogger;
class EPollEventManager;

class EPollPoller : public Poller {
public:
  using EventList = std::vector<struct epoll_event>;
  using UniqueLogger = std::unique_ptr<EPollLogger>;
  using UniqueEventManager = std::unique_ptr<EPollEventManager>;

  explicit EPollPoller(EventLoop *loop);
  ~EPollPoller() override;

  TimeStamp poll(int timeoutMs, ChannelList *activeChannels) override;
  void updateChannel(Channel *channel) override;
  void removeChannel(Channel *channel) override;
  bool hasChannel(Channel *channel) const override;

private:
  static constexpr int kInitEventListSize = 16;

  int epollfd_;
  EventList events_;
  UniqueLogger logger_;
  UniqueEventManager eventManager_;
};

class EPollLogger {
public:
  using LogMessage = std::string;

  void logError(const LogMessage &message) const;
  void logEpollCreateError() const;
  void logChannelOperationError(const LogMessage &operation) const;
};

class EPollEventManager {
public:
  explicit EPollEventManager(int epollfd);

  void addChannel(Channel *channel);
  void modifyChannel(Channel *channel);
  void removeChannel(Channel *channel);
  bool hasChannel(Channel *channel) const;
  void fillActiveChannels(const EPollPoller::EventList &events,
                          int numEvents,
                          ChannelList *activeChannels) const;

private:
  struct EPollOperation {
    static constexpr int ADD = EPOLL_CTL_ADD;
    static constexpr int MODIFY = EPOLL_CTL_MOD;
    static constexpr int REMOVE = EPOLL_CTL_DEL;
  };

  using OperationName = std::string;

  epoll_event createEpollEvent(Channel *channel) const;
  void executeEpollControl(int operation, Channel *channel);
  OperationName getOperationName(int operation) const;

  int epollfd_;
  ChannelMap channels_;
};

} // namespace server
