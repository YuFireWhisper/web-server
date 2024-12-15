#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <poll.h>
#include <set>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sys/epoll.h>

namespace server {
class TimeStamp;
class Timer;
class Channel;
class Poller;
class EventLoop;

using EventCallback     = std::function<void()>;
using ReadEventCallback = std::function<void(TimeStamp)>;

using Functor = std::function<void()>;

struct EventType {
  static const int kNoneEvent  = 0;
  static const int kReadEvent  = EPOLLIN | EPOLLPRI;
  static const int kWriteEvent = EPOLLOUT;
  static const int kErrorEvent = EPOLLERR;
  static const int kCloseEvent = EPOLLHUP;
};

enum class PollerState : std::int8_t { kNew = -1, kAdded = 1, kDeleted = 2 };

using TimerCallback = std::function<void()>;
using TimerEntry    = std::pair<TimeStamp, Timer *>;
using TimerList     = std::set<TimerEntry>;

using ChannelList = std::vector<Channel *>;
using ChannelMap  = std::unordered_map<int, Channel *>;

static constexpr int kTimeScaleFactor       = 1000;
static constexpr int kMillisecondPerSecond  = kTimeScaleFactor;
static constexpr int kMicroSecondsPerSecond = kMillisecondPerSecond * kTimeScaleFactor;
static constexpr int kNanosecondPerSecond   = kMicroSecondsPerSecond * kTimeScaleFactor;

static constexpr size_t kKib = 1024;
static constexpr size_t kMib = kKib * 1024;
static constexpr size_t kGib = kMib * 1024;

static constexpr size_t kDefaultHighWaterMark = kMib * 64;

using ThreadInitCallback = std::function<void(EventLoop *)>;

static constexpr std::string_view kCRLF{"\r\n"};
static constexpr std::string_view kCRLFCRLF{"\r\n\r\n"};

enum class Version : int8_t { kUnknown, kHttp10, kHttp11 };

enum class CommandType : uint32_t {
  configNoArgs = 0x00000001,
  configTake1  = 0x00000002,
  configTake2  = 0x00000004,
  configTake3  = 0x00000008,
  configFlag   = 0x00000100,
  configNumber = 0x00000200,
  configString = 0x00000400,
  global       = 0x00010000,
  server       = 0x00020000,
  http         = 0x00040000,
  location     = 0x00080000,
};

using ConfigPtr = std::shared_ptr<void>;

struct ServerCommand {
  std::string name;
  CommandType type;
  size_t offset;
  std::function<char *(ConfigPtr, const std::string, size_t)> set;
  std::function<void *(ConfigPtr)> post;
};
} // namespace server
