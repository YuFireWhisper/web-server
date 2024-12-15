#pragma once

#include "include/types.h"

#include <string>
#include <unordered_map>

namespace server {

class ConfigManager {
public:
  void registerCommand(const ServerCommand &cmd);
  void registerCommands(const std::vector<ServerCommand> &cmds);

  bool handleCommand(const std::string &name, const std::string &value, const ConfigPtr &conf);
  
private:
  std::unordered_map<std::string, ServerCommand> commands_;
};

inline CommandType operator|(CommandType first, CommandType second) {
  return static_cast<CommandType>(
      static_cast<std::underlying_type_t<CommandType>>(first)
      | static_cast<std::underlying_type_t<CommandType>>(second)
  );
}

inline CommandType &operator|=(CommandType &first, CommandType second) {
  first = first | second;
  return first;
}

inline bool operator&(CommandType first, CommandType second) {
  return static_cast<bool>(
      static_cast<std::underlying_type_t<CommandType>>(first)
      & static_cast<std::underlying_type_t<CommandType>>(second)
  );
}

} // namespace server
