#pragma once

#include "types.h"

namespace server {

class EventLoop;
class TimeStamp;

class Channel {
public:
  Channel(EventLoop *loop, int fd);
  ~Channel();

  void handleEvent(TimeStamp receiveTime);
  void handleEventWithGuard(TimeStamp receiveTime);

  void setReadCallback(const ReadEventCallback &cb) { readCallback_ = cb; }
  void setWriteCallback(const EventCallback &cb) { writeCallback_ = cb; }
  void setErrorCallback(const EventCallback &cb) { errorCallback_ = cb; }
  void setCloseCallback(const EventCallback &cb) { closeCallback_ = cb; }

  void enableReading() { updateEventStatus(events_ | EventType::kReadEvent); }
  void disableReading() { updateEventStatus(events_ & ~EventType::kReadEvent); }
  void enableWriting() { updateEventStatus(events_ | EventType::kWriteEvent); }
  void disableWriting() { updateEventStatus(events_ & ~EventType::kWriteEvent); }
  void disableAll() { updateEventStatus(EventType::kNoneEvent); }
  void remove();

  bool isWriting() const { return events_ & EventType::kWriteEvent; }
  bool isReading() const { return events_ & EventType::kReadEvent; }
  bool isNoneEvent() const { return events_ == EventType::kNoneEvent; }
  bool isInLoop() const;

  int fd() const { return fd_; }
  int events() const { return events_; }
  void setRevents(int revt) { revents_ = revt; }
  int index() const { return index_; }
  void setIndex(int idx) { index_ = idx; }
  EventLoop *ownerLoop() const { return loop_; }

  void assertInLoop();

private:
  void processEvents(TimeStamp time);
  void updateEventStatus(int events);
  void notifyLoopOfUpdate();
  void cleanupResources();

  EventLoop *const loop_;
  const int fd_;
  int events_;
  int revents_;
  int index_;
  bool addedToLoop_;
  bool eventHandling_;

  ReadEventCallback readCallback_;
  EventCallback writeCallback_;
  EventCallback errorCallback_;
  EventCallback closeCallback_;
};

} // namespace server
