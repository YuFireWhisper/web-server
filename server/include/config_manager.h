#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

#include <string>
#include <unordered_map>

namespace server {

class ConfigManager {
public:
  static ConfigManager &getInstance() {
    static ConfigManager instance;
    return instance;
  }
  ConfigManager(const ConfigManager &)            = delete;
  ConfigManager &operator=(const ConfigManager &) = delete;
  void registerCommand(const ServerCommand &cmd);
  void registerCommands(const std::vector<ServerCommand> &cmds);
  void handleCommand(std::vector<std::string> field);
  void configParse(const char *data, size_t len);
  ConfigContext &getCurrentContext();
  void setCurrentText(const ConfigContext &context);
  void *getContextByOffset(size_t offset);
  void *getConfigByOffset(size_t offset);

private:
  ConfigManager();
  static size_t findNext(const char *data, char target, size_t len);
  static bool handleBlockEnd(ConfigContext &context);
  static bool hasFlag(CommandType input, CommandType flag);
  static bool setParentContext(ConfigContext &context);
  CommandType getContextType(ConfigContext *context);

  ConfigContext context_;
  std::unordered_map<std::string, ServerCommand> commands_;
};
} // namespace server
