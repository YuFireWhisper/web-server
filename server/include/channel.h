#pragma once

#include "include/types.h"

namespace server {

class EventLoop;
class TimeStamp;

class Channel {
public:
  Channel(EventLoop *loop, int fd);
  ~Channel();

  Channel(const Channel &)            = delete;
  Channel &operator=(const Channel &) = delete;
  Channel(Channel &&)                 = delete;
  Channel &operator=(Channel &&)      = delete;

  void handleEvent(TimeStamp receiveTime);
  void handleEventWithGuard(TimeStamp receiveTime);

  void setReadCallback(ReadEventCallback &&cb) { readCallback_ = std::move(cb); }
  void setWriteCallback(EventCallback &&cb) { writeCallback_ = std::move(cb); }
  void setErrorCallback(EventCallback &&cb) { errorCallback_ = std::move(cb); }
  void setCloseCallback(EventCallback &&cb) { closeCallback_ = std::move(cb); }

  void enableReading() { updateEventStatus(static_cast<int>(events_ | kReadEvent)); }
  void disableReading() { updateEventStatus(static_cast<int>(events_ & ~kReadEvent)); }
  void enableWriting() { updateEventStatus(static_cast<int>(events_ | kWriteEvent)); }
  void disableWriting() { updateEventStatus(static_cast<int>(events_ & ~kWriteEvent)); }
  void disableAll() { updateEventStatus(kNoneEvent); }
  void remove();

  [[nodiscard]] bool isWriting() const { return (events_ & kWriteEvent) != 0; }
  [[nodiscard]] bool isReading() const { return (events_ & kReadEvent) != 0; }
  [[nodiscard]] bool isNoneEvent() const { return events_ == kNoneEvent; }
  [[nodiscard]] bool isInLoop() const;

  [[nodiscard]] int fd() const { return fd_; }
  [[nodiscard]] int events() const { return events_; }
  void setRevents(int revt) { revents_ = revt; }
  [[nodiscard]] int index() const { return index_; }
  void setIndex(int idx) { index_ = idx; }
  [[nodiscard]] EventLoop *ownerLoop() const { return loop_; }

  void assertInLoop();

private:
  static constexpr int kNoneEvent           = 0;
  static constexpr unsigned int kReadEvent  = EPOLLIN | EPOLLPRI;
  static constexpr unsigned int kWriteEvent = EPOLLOUT;

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
