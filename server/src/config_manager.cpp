#include "include/config_manager.h"

#include "include/config_defaults.h"
#include "include/log.h"
#include "include/types.h"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/types.h>

namespace server {

ConfigManager::ConfigManager() {
  context_.now = kGlobalOffset;

  context_.globalContext   = new GlobalContext();
  context_.httpContext     = new HttpContext();
  context_.serverContext   = new ServerContext();
  context_.locationContext = new LocationContext();

  auto globalConfig            = std::make_unique<GlobalConfig>();
  context_.globalContext->conf = globalConfig.release();

  auto httpConfig              = std::make_unique<HttpConfig>();
  context_.httpContext->conf   = httpConfig.release();
  context_.httpContext->parent = context_.globalContext;

  auto serverConfig              = std::make_unique<ServerConfig>();
  context_.serverContext->conf   = serverConfig.release();
  context_.serverContext->parent = context_.httpContext;

  auto locationConfig              = std::make_unique<LocationConfig>();
  context_.locationContext->conf   = locationConfig.release();
  context_.locationContext->parent = context_.serverContext;
}

void ConfigManager::registerCommand(const ServerCommand &cmd) {
  commands_[cmd.name] = cmd;
}

void ConfigManager::registerCommands(const std::vector<ServerCommand> &cmds) {
  for (const auto &cmd : cmds) {
    registerCommand(cmd);
  }
}

size_t ConfigManager::findNext(const char *data, const char target, const size_t len) {
  const char *result = static_cast<const char *>(memchr(data, target, len));
  if (result != nullptr) {
    return result - data;
  }
  return len;
}

void ConfigManager::configParse(const char *data, const size_t len) {
  if (len <= 0) {
    std::string message =
        "Data length cannot be a non-positive! Input length: " + std::to_string(len);
    LOG_FATAL(message);
    throw std::invalid_argument(message);
  }

  std::string word;
  std::vector<std::string> wordVector;

  for (size_t i = 0; i < len; ++i) {
    if (data[i] == '#') {
      size_t result = findNext(data + i, '\n', len - i);
      if (result == len - i) {
        return;
      }
      i = result;
      continue;
    }

    if (std::isspace(data[i]) != 0 && word.empty()) {
      continue;
    }

    if (std::isspace(data[i]) != 0 && !word.empty()) {
      wordVector.push_back(word);
      word = "";
    }

    if (data[i] == '{') {
      continue;
    }

    if (data[i] == ';') {
      handleCommand(wordVector);
    }

    if (data[i] == '}') {
      bool result = setParentContext(context_);
      if (result) {
        return;
      }
    }

    word += data[i];
  }
}

void ConfigManager::handleCommand(std::vector<std::string> field) {
  auto it = commands_.find(field[0]);

  if (it == commands_.end()) {
    std::string message = "Cannot find config name: " + field[0];
    LOG_FATAL(message);
    throw std::invalid_argument(message);
  }

  field.erase(field.begin());

  CommandType contextType = getContextType(&context_);

  if (!hasFlag(contextType, it->second.type)) {
    std::string message = "Config at wrong place!";
    LOG_FATAL(message);
    throw std::invalid_argument(message);
  }

  const auto &cmd = it->second;


  auto cmdType       = static_cast<uint32_t>(cmd.type);
  uint32_t argsType  = cmdType & argsMask;
  uint32_t valueType = cmdType & typeMask;

  bool is1more = hasFlag(cmd.type, CommandType::config1more);
  bool is2more = hasFlag(cmd.type, CommandType::config2more);

  uint32_t expectedArgs = 0;
  if (!is1more && !is2more) {
    while (argsType > 1) {
      argsType >>= 1;
      expectedArgs++;
    }

    bool validArgs = field.empty() ? (expectedArgs == 0) : (field.size() == expectedArgs - 1);
    if (!validArgs) {
      std::string message = "Args is not valid! Expected: " + std::to_string(expectedArgs)
                            + ", Actual: " + std::to_string(field.size());
      LOG_FATAL(message);
      throw std::invalid_argument(message);
    }
  } else {
    size_t minArgs = is1more ? 1 : 2;
    if (field.size() < minArgs) {
      std::string message = "Args is not valid! Expected at least: " + std::to_string(minArgs)
                            + ", Actual: " + std::to_string(field.size());
      LOG_FATAL(message);
      throw std::invalid_argument(message);
    }
  }

  if (cmd.set) {
    cmd.set(field, getContextByOffset(context_.now), it->second.offset);
  }

  if (valueType == 0) {
    return;
  }

  try {
    auto *ctx  = getConfigByOffset(cmd.offset);
    char *base = reinterpret_cast<char *>(&ctx);

    switch (valueType) {
      case static_cast<uint32_t>(CommandType::configFlag):
        *reinterpret_cast<bool *>(base + cmd.offset) =
            (field[0] == "on" || field[0] == "true" || field[0] == "1");
        break;

      case static_cast<uint32_t>(CommandType::configNumber):
        *reinterpret_cast<int *>(base + cmd.offset) = std::stoi(field[0]);
        break;

      case static_cast<uint32_t>(CommandType::configString):
        *reinterpret_cast<std::string *>(base + cmd.offset) = field[0];
        break;
      case static_cast<uint32_t>(CommandType::configSizeT):
        *reinterpret_cast<size_t *>(base + cmd.offset) = std::stoul(field[0]);
        break;

      default:
        std::string message = "No matching type!";
        LOG_FATAL(message);
        throw std::invalid_argument(message);
    }

  } catch (const std::exception &e) {
    LOG_FATAL(e.what());
    throw e;
  }
}

void *ConfigManager::getContextByOffset(size_t offset) {
  if (offset >= sizeof(ConfigContext)) {
    throw std::out_of_range("Invalid context offset");
  }

  char *base = reinterpret_cast<char *>(&context_);
  void **ptr = reinterpret_cast<void **>(base + offset);

  if (*ptr == nullptr) {
    throw std::runtime_error("Null context pointer");
  }

  return *ptr;
}

CommandType ConfigManager::getContextType(ConfigContext *context) {
  void *ctx = getContextByOffset(context->now);
  if (ctx == nullptr) {
    throw std::runtime_error("Invalid context");
  }
  return static_cast<ContextBase *>(ctx)->typeB;
}

bool ConfigManager::hasFlag(CommandType input, CommandType flag) {
  return (static_cast<uint32_t>(input) & static_cast<uint32_t>(flag)) != 0;
}

bool ConfigManager::setParentContext(ConfigContext &context) {
  if (context.now == kLocationOffset) {
    context.now = kServerOffset;
    return true;
  }

  if (context.now == kServerOffset) {
    context.now = kHttpOffset;
    return true;
  }

  if (context.now == kHttpOffset) {
    context.now = kGlobalOffset;
    return true;
  }

  return false;
}

ConfigContext &ConfigManager::getCurrentContext() {
  return context_;
}

void ConfigManager::setCurrentText(const ConfigContext &context) {
  context_ = context;
}

void* ConfigManager::getConfigByOffset(size_t offset) {
  auto* ctx = static_cast<ContextBase*>(getContextByOffset(offset));
  return ctx->confB;
}
} // namespace server
