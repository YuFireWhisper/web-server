#include "include/config_manager.h"

#include "include/types.h"

#include <cstdint>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include <sys/types.h>

namespace server {

void ConfigManager::registerCommand(const ServerCommand &cmd) {
  commands_[cmd.name] = cmd;
}

void ConfigManager::registerCommands(const std::vector<ServerCommand> &cmds) {
  for (const auto &cmd : cmds) {
    registerCommand(cmd);
  }
}

bool ConfigManager::handleCommand(
    const std::string &name,
    const std::string &value,
    const ConfigPtr &conf
) {
  auto it = commands_.find(name);

  if (it == commands_.end()) {
    return false;
  }

  const auto &cmd = it->second;

  if (cmd.set) {
    return cmd.set(conf, value, cmd.offset) == nullptr;
  }

  const uint32_t argsMask = 0x000000FF;
  const uint32_t typeMask = 0x0000FF00;

  auto cmdType       = static_cast<uint32_t>(cmd.type);
  uint32_t argsType  = cmdType & argsMask;
  uint32_t valueType = cmdType & typeMask;

  uint32_t expected_args = 0;
  while (argsType > 1) {
    argsType >>= 1;
    expected_args++;
  }

  bool validArgs = value.empty()
                       ? (expected_args == 0)
                       : (std::count(value.begin(), value.end(), ' ') == expected_args - 1);

  if (!validArgs) {
    return false;
  }

  if (valueType == 0) {
    return true;
  }

  try {
    auto *config = conf.get();
    char *base   = reinterpret_cast<char *>(config);

    switch (valueType) {
      case static_cast<uint32_t>(CommandType::configFlag):
        *reinterpret_cast<bool *>(base + cmd.offset) =
            (value == "on" || value == "true" || value == "1");
        break;

      case static_cast<uint32_t>(CommandType::configNumber):
        *reinterpret_cast<int *>(base + cmd.offset) = std::stoi(value);
        break;

      case static_cast<uint32_t>(CommandType::configString):
        *reinterpret_cast<std::string *>(base + cmd.offset) = value;
        break;

      default:
        return false;
    }

    return true;
  } catch (const std::exception &) {
    return false;
  }
}
} // namespace server
