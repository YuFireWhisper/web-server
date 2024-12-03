#pragma once

#include "include/time_stamp.h"
#include "poller.h"
#include "types.h"

#include <vector>

#include <sys/epoll.h>

namespace server {

class EPollPoller : public Poller {
public:
  EPollPoller(EventLoop *loop);
  ~EPollPoller() override;

  TimeStamp poll(int timeoutMs, ChannelList *activeChannels) override;
  void updateChannel(Channel *channel) override;
  void removeChannel(Channel *channel) override;  

private:
  typedef std::vector<struct epoll_event> EventList;

  static const int kInitEventListSize = 16;
  static const char *operationToString(int op);

  void fillActiveChannels();
  void update(int operation);

  ChannelList *activeChannels_;

  int epollfd_;
  EventList events_;

  int timeoutMs_;
  int numEvent_;

  int channelIndex_;
  int channelFd_;
  Channel *channel_;

  struct epoll_event event_;
  int operation_;
  int updateReturnVal_;

private:
  void checkCreateStatus();
  TimeStamp checkPollStatus();
  void checkEventSize();

  bool hasError() const;
  bool hasEvents() const;
  void handleError();
  bool isInterrupted() const;
  void retryPoll();
  void logError();
  void processEvents();

  bool isNewStatus() const;
  void handleNewStatus();
  bool isDelStatus() const;
  void handleDelStatus();
  void setIndexToAdd();
  bool isNoneEventChannel() const;
  void handleNoneEventChannel();
  void setIndexToDel();

  void setEventForUpdate();
  void updateWithEpollCtl();
  bool isUpdateFailed() const;
  void handleUpdateFailed();
  void logForDelOperation();
  void handleNotDelOperation();

  void eraseChannel();
  void setIndexToNew();
};
} // namespace server
