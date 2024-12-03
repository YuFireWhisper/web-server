#pragma once

#include "include/types.h"
#include <functional>
#include <poll.h>

#include <sys/epoll.h>

namespace server {
class EventLoop;
class TimeStamp;

class Channel {
public:
  typedef std::function<void()> EventCallback;
  typedef std::function<void(TimeStamp)> ReadEventCallback;

  Channel(EventLoop *loop, int fd);
  ~Channel();

  void handleEvent(TimeStamp receiveTime);
  void handleEventWithGuard(TimeStamp receiveTime);

  void setReadCallback(const ReadEventCallback &cb) { readCallback_ = cb; }
  void setWriteCallback(const EventCallback &cb) { writeCallback_ = cb; }
  void setErrorCallback(const EventCallback &cb) { errorCallback_ = cb; }
  void setCloseCallback(const EventCallback &cb) { closeCallback_ = cb; }

  void enableReading() {
    events_ |= EventType::kReadEvent;
    update();
  }
  void disableReading() {
    events_ &= ~EventType::kReadEvent;
    update();
  }
  void enableWriting() {
    events_ |= EventType::kWriteEvent;
    update();
  }
  void disableWriting() {
    events_ &= ~EventType::kWriteEvent;
    update();
  }
  void disableAll() {
    events_ = EventType::kNoneEvent;
    update();
  }

  bool isWriting() const { return events_ & EventType::kWriteEvent; }
  bool isReading() const { return events_ & EventType::kReadEvent; }
  bool isNoneEvent() const { return events_ == EventType::kNoneEvent; }

  int fd() const { return fd_; }
  int events() const { return events_; }
  void set_revents(int revt) { revents_ = revt; }

  int index() const { return index_; }
  void set_index(int idx) { index_ = idx; }

  EventLoop *ownerLoop() const { return loop_; }

  void remove();
  bool isInLoop() const;
  void assertInLoop();

private:
  void update();

  EventLoop *const loop_;
  const int fd_;
  int events_;
  int revents_;
  bool addedToLoop_;
  bool eventHandling_;
  int index_;

  ReadEventCallback readCallback_;
  EventCallback writeCallback_;
  EventCallback errorCallback_;
  EventCallback closeCallback_;
};

} // namespace server
