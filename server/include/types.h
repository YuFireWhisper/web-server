#pragma once

#include <functional>
#include <poll.h>
#include <set>
#include <unordered_map>
#include <vector>

#include <sys/epoll.h>

namespace server {
class TimeStamp;
class Timer;
class Channel;
class Poller;
class EventLoop;

using EventCallback = std::function<void()>;
using ReadEventCallback = std::function<void(TimeStamp)>;

using Functor = std::function<void()>;

struct EventType {
  static const int kNoneEvent = 0;
  static const int kReadEvent = EPOLLIN | EPOLLPRI;
  static const int kWriteEvent = EPOLLOUT;
  static const int kErrorEvent = EPOLLERR;
  static const int kCloseEvent = EPOLLHUP;
};

enum class PollerState { kNew = -1, kAdded = 1, kDeleted = 2 };

using TimerCallback = std::function<void()>;
using TimerEntry = std::pair<TimeStamp, Timer *>;
using TimerList = std::set<TimerEntry>;

using ChannelList = std::vector<Channel *>;
using ChannelMap = std::unordered_map<int, Channel *>;

static constexpr int MicroSecondsPerSecond = 1000 * 1000;

using ThreadInitCallback = std::function<void(EventLoop *)>;
} // namespace server
