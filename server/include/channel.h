#pragma once

#include <functional>
#include <memory>
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

  void setReadCallback(const ReadEventCallback &cb) {
    readCallback_ = cb;
  }
  void setWriteCallback(const EventCallback &cb) {
    writeCallback_ = cb;
  }
  void setErrorCallback(const EventCallback &cb) {
    errorCallback_ = cb;
  }
  void setCloseCallback(const EventCallback &cb) {
    closeCallback_ = cb;
  }

  void enableReading() {
    events_ |= kReadEvent;
    update();
  }
  void disableReading() {
    events_ &= ~kReadEvent;
    update();
  }
  void enableWriting() {
    events_ |= kWriteEvent;
    update();
  }
  void disableWriting() {
    events_ &= ~kWriteEvent;
    update();
  }
  void disableAll() {
    events_ = kNoneEvent;
    update();
  }

  bool isWriting() const {
    return events_ & kWriteEvent;
  }
  bool isReading() const {
    return events_ & kReadEvent;
  }
  bool isNoneEvent() const {
    return events_ == kNoneEvent;
  }

  int fd() const {
    return fd_;
  }
  int events() const {
    return events_;
  }

  void set_revents(int revt) {
    revents_ = revt;
  }

  EventLoop *ownerLoop() {
    return loop_;
  }

  void tie(const std::shared_ptr<void> &obj);

  void remove();

private:
  void update();

  static const int kNoneEvent = 0;
  static const int kReadEvent = POLLIN | POLLPRI;
  static const int kWriteEvent = POLLOUT;

#ifdef USE_EPOLL
  static int eventsToEpoll(int events) {
    int epollEvents = 0;
    if (events & kReadEvent)
      epollEvents |= EPOLLIN | EPOLLPRI;
    if (events & kWriteEvent)
      epollEvents |= EPOLLOUT;
    return epollEvents;
  }

  static int epollToEvents(int epollEvents) {
    int events = kNoneEvent;
    if (epollEvents & (EPOLLIN | EPOLLPRI))
      events |= kReadEvent;
    if (epollEvents & EPOLLOUT)
      events |= kWriteEvent;
    if (epollEvents & EPOLLERR)
      events |= POLLERR;
    if (epollEvents & EPOLLHUP)
      events |= POLLHUP;
    return events;
  }
#endif

  EventLoop *loop_;
  const int fd_;
  int events_;
  int revents_;
  bool tied_;
  bool eventHandling_;
  bool addedToLoop_;

  std::weak_ptr<void> tie_;

  ReadEventCallback readCallback_;
  EventCallback writeCallback_;
  EventCallback errorCallback_;
  EventCallback closeCallback_;
};

} // namespace server
