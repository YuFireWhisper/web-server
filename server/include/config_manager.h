#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace server {

class ConfigManager {
public:
  static ConfigManager &getInstance();
  ~ConfigManager();

  void registerCommand(const ServerCommand &cmd);
  void registerCommands(const std::vector<ServerCommand> &cmds);
  void handleCommand(std::vector<std::string> field);
  void configParse(const char *data, size_t len);
  ConfigContext &getCurrentContext();
  void setCurrentContext(const ConfigContext &context);
  void *getContextByOffset(size_t offset) const;
  void *getConfigByOffset(size_t offset) const;

private:
  ConfigManager();

  static size_t findWordEnd(const char *data, size_t len);
  static bool setParentContext(ConfigContext &context);
  static bool hasCommandFlag(CommandType input, CommandType flag);
  static void handleLocationEnd(LocationContext *ctx);
  static void handleServerEnd(ServerContext* ctx);
  static void updateConfigValue(void *basePtr, const ServerCommand &cmd, const std::string &value);

  static bool validateCommandArgs(CommandType type, size_t argCount);
  static uint32_t getCommandArgBits(CommandType type);

  static void processComment(const char *data, size_t len, size_t &pos);
  void processBlockStart(std::string &word, std::vector<std::string> &words);
  void processBlockEnd(std::string &word, std::vector<std::string> &words);
  static void processCharacter(char c, std::string &word);

  CommandType getContextType(ConfigContext *context) const;
  void processCommandField(const std::vector<std::string> &field, const ServerCommand &cmd) const;

  ConfigContext context_;
  std::unordered_map<std::string, ServerCommand> commands_;
};

} // namespace server
