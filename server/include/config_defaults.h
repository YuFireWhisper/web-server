#pragma once

#include "include/types.h"

#include <cstddef>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <vector>

#define OFFSET_OF(type, member)                                                                    \
  (reinterpret_cast<size_t>(&reinterpret_cast<char const volatile &>(((type *)0)->member)))

namespace server {

struct ServerConfig {
  in_port_t port   = 8080;
  std::string ip   = "0.0.0.0";
  bool reusePort   = false;
  size_t threadNum = std::thread::hardware_concurrency();
};

struct HttpConfig {
  size_t maxHeaderSize                    = kKib * 8;
  size_t maxBodySize                      = kMib;
  size_t keepAliveTimeout                 = 60;
  std::string serverName                  = "MyServer";
  std::vector<std::string> allowedMethods = {"GET", "POST", "HEAD"};
};

struct BufferConfig {
  size_t initialSize     = kKib;
  size_t maxSize         = kMib * 64;
  size_t extraBufferSize = kKib * 64;
  size_t prependSize     = 8;
  size_t highWaterMark   = kDefaultHighWaterMark;
};

struct LogConfig {
  std::string systemLogPath = "logs/system.log";
};

struct TcpConfig {
  bool tcpNoDelay       = true;
  bool keepAlive        = true;
  int keepAliveIdle     = 60;
  int keepAliveInterval = 30;
  int keepAliveCount    = 3;
};

struct TimerConfig {
  int timerCheckInterval = 100;
  size_t maxTimers       = 10000;
};

struct EventLoopConfig {
  int pollTimeoutMs = 10000;
  size_t maxEvents  = 4096;
};

} // namespace server
