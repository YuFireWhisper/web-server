#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
namespace server {

enum class CommandType : uint32_t {
  configNoArgs = 0x00000001,
  configTake1  = 0x00000002,
  configTake2  = 0x00000004,
  configTake3  = 0x00000008,
  configBool   = 0x00000100,
  global       = 0x00010000,
  server       = 0x00020000,
  http         = 0x00040000,
  location     = 0x00080000,
};

using ConfigPtr = std::shared_ptr<void>;

struct ServerCommand {
  std::string name;
  CommandType type;
  std::function<char *(ConfigPtr, const std::string)> set;
  std::function<void *(ConfigPtr)> post;
};

class ConfigManager {
public:
  void registerCommand(const ServerCommand &cmd);
  void registerCommands(const std::vector<ServerCommand> &cmds);

  bool handleCommand(const std::string &name, const std::string &value, const ConfigPtr &conf);

private:
  std::unordered_map<std::string, ServerCommand> commands_;
};

} // namespace server
