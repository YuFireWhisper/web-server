#include "include/config_manager.h"
#include "include/types.h"

#include <cstddef>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <vector>

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
  size_t initialSize   = kKib;
  size_t maxSize       = kMib * 64;
  size_t highWaterMark = kDefaultHighWaterMark;
};

struct LogConfig {
  std::string systemLogPath  = "logs/system.log";
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

std::vector<ServerCommand> getServerCommands() {
  return {
      {"port", CommandType::configTake1 | CommandType::server},
      {"listen", CommandType::configTake1 | CommandType::server},
      {"worker_processes", CommandType::configTake1 | CommandType::server},
      {"reuse_port", CommandType::configBool | CommandType::server},
  };
}

std::vector<ServerCommand> getHttpCommands() {
  return {
      {"client_max_body_size", CommandType::configTake1 | CommandType::http},
      {"client_header_timeout", CommandType::configTake1 | CommandType::http},
      {"keepalive_timeout", CommandType::configTake1 | CommandType::http},
      {"server_name", CommandType::configTake1 | CommandType::http},
      {"allowed_methods", CommandType::configTake1 | CommandType::http},
  };
}

std::vector<ServerCommand> getBufferCommands() {
  return {
      {"buffer_initial_size", CommandType::configTake1 | CommandType::global},
      {"buffer_max_size", CommandType::configTake1 | CommandType::global},
      {"buffer_high_water_mark", CommandType::configTake1 | CommandType::global},
  };
}

std::vector<ServerCommand> getLogCommands() {
  return {
      {"system_log_path", CommandType::configTake1 | CommandType::global},
  };
}

std::vector<ServerCommand> getTcpCommands() {
  return {
      {"tcp_nodelay", CommandType::configBool | CommandType::server},
      {"tcp_keepalive", CommandType::configBool | CommandType::server},
      {"keepalive_idle", CommandType::configTake1 | CommandType::server},
      {"keepalive_interval", CommandType::configTake1 | CommandType::server},
      {"keepalive_count", CommandType::configTake1 | CommandType::server},
  };
}

std::vector<ServerCommand> getTimerCommands() {
  return {
      {"timer_check_interval", CommandType::configTake1 | CommandType::global},
      {"max_timers", CommandType::configTake1 | CommandType::global},
  };
}

std::vector<ServerCommand> getEventLoopCommands() {
  return {
      {"poll_timeout", CommandType::configTake1 | CommandType::global},
      {"max_events", CommandType::configTake1 | CommandType::global},
  };
}

} // namespace server
