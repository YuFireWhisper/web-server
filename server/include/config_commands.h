#include "include/buffer.h"
#include "include/config_defaults.h"
#include "include/config_manager.h"
#include "include/types.h"

#include <vector>

namespace server {

inline std::vector<ServerCommand> getServerCommands() {
  return {
      {"port", CommandType::configTake1 | CommandType::server},
      {"listen", CommandType::configTake1 | CommandType::server},
      {"worker_processes", CommandType::configTake1 | CommandType::server},
      {"reuse_port", CommandType::configFlag | CommandType::server},
  };
}

inline std::vector<ServerCommand> getHttpCommands() {
  return {
      {"client_max_body_size", CommandType::configTake1 | CommandType::http},
      {"client_header_timeout", CommandType::configTake1 | CommandType::http},
      {"keepalive_timeout", CommandType::configTake1 | CommandType::http},
      {"server_name", CommandType::configTake1 | CommandType::http},
      {"allowed_methods", CommandType::configTake1 | CommandType::http},
  };
}

inline std::vector<ServerCommand> getBufferCommands() {
  return {
      {"buffer_initial_size",
       CommandType::configTake1 | CommandType::global,
       OFFSET_OF(BufferConfig, initialSize),
       Buffer::handleConfigSize,
       nullptr},
      {"buffer_max_size",
       CommandType::configTake1 | CommandType::global,
       OFFSET_OF(BufferConfig, maxSize),
       Buffer::handleConfigSize,
       nullptr},
      {"buffer_extra_buffer_size",
       CommandType::configTake1 | CommandType::global,
       OFFSET_OF(BufferConfig, extraBufferSize),
       Buffer::handleConfigSize,
       nullptr},
      {"buffer_prepend_size",
       CommandType::configTake1 | CommandType::global,
       OFFSET_OF(BufferConfig, prependSize),
       Buffer::handleConfigSize,
       nullptr},
      {"buffer_high_water_mark",
       CommandType::configTake1 | CommandType::global,
       OFFSET_OF(BufferConfig, highWaterMark),
       Buffer::handleConfigSize,
       nullptr},
      {"buffer_config_done",
       CommandType::configNoArgs | CommandType::global,
       0,
       nullptr,
       Buffer::postCheckConfig},
  };
}

inline std::vector<ServerCommand> getLogCommands() {
  return {
      {"system_log_path", CommandType::configTake1 | CommandType::global},
  };
}

inline std::vector<ServerCommand> getTcpCommands() {
  return {
      {"tcp_nodelay", CommandType::configFlag | CommandType::server},
      {"tcp_keepalive", CommandType::configFlag | CommandType::server},
      {"keepalive_idle", CommandType::configTake1 | CommandType::server},
      {"keepalive_interval", CommandType::configTake1 | CommandType::server},
      {"keepalive_count", CommandType::configTake1 | CommandType::server},
  };
}

inline std::vector<ServerCommand> getTimerCommands() {
  return {
      {"timer_check_interval", CommandType::configTake1 | CommandType::global},
      {"max_timers", CommandType::configTake1 | CommandType::global},
  };
}

inline std::vector<ServerCommand> getEventLoopCommands() {
  return {
      {"poll_timeout", CommandType::configTake1 | CommandType::global},
      {"max_events", CommandType::configTake1 | CommandType::global},
  };
}

inline void initialAll() {
  ConfigManager configManager;
  configManager.registerCommands(getBufferCommands());

  static ConfigPtr config = std::make_shared<BufferConfig>();
  configManager.handleCommand("buffer_initial_size", "1024", config);
  configManager.handleCommand("buffer_max_size", "65536", config);
  configManager.handleCommand("buffer_extra_buffer_size", "65536", config);
  configManager.handleCommand("buffer_prepend_size", "8", config);
  configManager.handleCommand("buffer_high_water_mark", "65536", config);
  configManager.handleCommand("buffer_config_done", "", config);
}
} // namespace server
