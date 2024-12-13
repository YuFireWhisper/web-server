#include "include/config_manager.h"

#include <vector>

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

  if (it->second.set) {
    char *result = it->second.set(conf, value);
    if (result != nullptr) {
      return false;
    }
  }

  if (it->second.post) {
    void *post_result = it->second.post(conf);
    if (post_result != nullptr) {
      return false;
    }
  }

  return true;
}
} // namespace server
