#pragma once

#include <functional>
#include <poll.h>
#include <set>
#include <vector>
#include <unordered_map>

namespace server {
class TimeStamp;
class Timer;
class Channel;

using EventCallback = std::function<void()>;
using ReadEventCallback = std::function<void(TimeStamp)>;

using Functor = std::function<void()>;

struct EventType {
  static const int kNoneEvent = 0;
  static const int kReadEvent = POLLIN | POLLPRI;
  static const int kWriteEvent = POLLOUT;
  static const int kErrorEvent = POLLERR;
  static const int kCloseEvent = POLLHUP;
};

using TimerCallback = std::function<void()>;
using TimerEntry = std::pair<TimeStamp, Timer *>;
using TimerList = std::set<TimerEntry>;

using ChannelList = std::vector<Channel *>;
using ChannelMap = std::unordered_map<int, Channel *>;

static constexpr int MicroSecondsPerSecond = 1000 * 1000;
} // namespace server
