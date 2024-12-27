#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

#include <vector>

namespace server {

inline std::vector<ServerCommand> getGlobalCommands() {
  return {
    { "system_log_path",
      CommandType::configTake1 | CommandType::configString | CommandType::global,
      0,
      OFFSET_OF(GlobalConfig, systemLogPath),
      nullptr,
      nullptr },
    { "timer_check_interval",
      CommandType::configTake1 | CommandType::configNumber | CommandType::global,
      0,
      OFFSET_OF(GlobalConfig, timerCheckInterval),
      nullptr,
      nullptr },
    { "max_timers",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::global,
      0,
      OFFSET_OF(GlobalConfig, maxTimers),
      nullptr,
      nullptr },
    { "poll_timeout",
      CommandType::configTake1 | CommandType::configNumber | CommandType::global,
      0,
      OFFSET_OF(GlobalConfig, pollTimeoutMs),
      nullptr,
      nullptr },
    { "max_events",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::global,
      0,
      OFFSET_OF(GlobalConfig, maxEvents),
      nullptr,
      nullptr },
    { "worker_processes",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::global,
      0,
      OFFSET_OF(GlobalConfig, threadNum),
      nullptr,
      nullptr },
  };
}

inline std::vector<ServerCommand> getHttpCommands() {
  return {
    { "http", CommandType::configNoArgs | CommandType::global, kHttpOffset, 0, nullptr, nullptr },
    { "client_max_body_size",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, maxBodySize),
      nullptr,
      nullptr },
    { "client_header_size",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, maxHeaderSize),
      nullptr,
      nullptr },
    { "keepalive_timeout",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, keepAliveTimeout),
      nullptr,
      nullptr },
    { "server_name",
      CommandType::configTake1 | CommandType::configString | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, serverName),
      nullptr,
      nullptr },
    { "buffer_initial_size",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, initialBufferSize),
      nullptr,
      nullptr },
    { "buffer_max_size",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, maxBufferSize),
      nullptr,
      nullptr },
    { "buffer_extra_size",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, extraBufferSize),
      nullptr,
      nullptr },
    { "buffer_prepend_size",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, prependSize),
      nullptr,
      nullptr },
    { "buffer_high_water_mark",
      CommandType::configTake1 | CommandType::configSizeT | CommandType::http,
      0,
      OFFSET_OF(HttpConfig, highWaterMark),
      nullptr,
      nullptr }
  };
}

inline std::vector<ServerCommand> getServerCommands() {
  return {
    { "server", CommandType::configNoArgs | CommandType::http, kServerOffset, 0, nullptr, nullptr },
    { "init_addr",
      CommandType::configTake1 | CommandType::configString | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, ip),
      nullptr,
      nullptr },
    { "listen",
      CommandType::configTake1 | CommandType::configNumber | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, port),
      nullptr,
      nullptr },
    { "reuse_port",
      CommandType::configTake1 | CommandType::configFlag | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, reusePort),
      nullptr,
      nullptr },
    { "tcp_nodelay",
      CommandType::configTake1 | CommandType::configFlag | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, tcpNoDelay),
      nullptr,
      nullptr },
    { "tcp_keepalive",
      CommandType::configTake1 | CommandType::configFlag | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, keepAlive),
      nullptr,
      nullptr },
    { "keepalive_idle",
      CommandType::configTake1 | CommandType::configNumber | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, keepAliveIdle),
      nullptr,
      nullptr },
    { "keepalive_interval",
      CommandType::configTake1 | CommandType::configNumber | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, keepAliveInterval),
      nullptr,
      nullptr },
    { "keepalive_count",
      CommandType::configTake1 | CommandType::configNumber | CommandType::server,
      0,
      OFFSET_OF(ServerConfig, keepAliveCount),
      nullptr,
      nullptr }
  };
}

inline std::vector<ServerCommand> getLocationCommands() {
  return { { "location",
             CommandType::configTake1 | CommandType::configString | CommandType::server,
             kLocationOffset,
             OFFSET_OF(LocationConfig, name),
             nullptr,
             nullptr },
           { "root",
             CommandType::configTake1 | CommandType::configString | CommandType::location,
             0,
             OFFSET_OF(LocationConfig, rootPath),
             nullptr,
             nullptr },
           { "proxy_pass",
             CommandType::configTake1 | CommandType::configString | CommandType::location,
             0,
             OFFSET_OF(LocationConfig, proxyPath),
             nullptr,
             nullptr },
           { "static_file",
             CommandType::configTake1 | CommandType::configString | CommandType::location,
             0,
             OFFSET_OF(LocationConfig, staticFile),
             nullptr,
             nullptr } };
}

inline std::vector<ServerCommand> getAllCommands() {
  std::vector<ServerCommand> commands;

  auto globalCommands   = getGlobalCommands();
  auto httpCommands     = getHttpCommands();
  auto serverCommands   = getServerCommands();
  auto locationCommands = getLocationCommands();

  commands.insert(commands.end(), globalCommands.begin(), globalCommands.end());
  commands.insert(commands.end(), httpCommands.begin(), httpCommands.end());
  commands.insert(commands.end(), serverCommands.begin(), serverCommands.end());
  commands.insert(commands.end(), locationCommands.begin(), locationCommands.end());

  return commands;
}

} // namespace server
