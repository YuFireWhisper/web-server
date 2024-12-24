#include "include/config_manager.h"

#include "include/config_defaults.h"
#include "include/log.h"
#include "include/router.h"
#include "include/types.h"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/types.h>

namespace server {

ConfigManager::ConfigManager() {
  auto globalConfig   = std::make_unique<GlobalConfig>();
  auto httpConfig     = std::make_unique<HttpConfig>();
  auto serverConfig   = std::make_unique<ServerConfig>();
  auto locationConfig = std::make_unique<LocationConfig>();

  context_.globalContext        = new GlobalContext();
  context_.globalContext->conf  = globalConfig.release();
  context_.globalContext->confB = context_.globalContext->conf;

  context_.httpContext         = new HttpContext();
  context_.httpContext->conf   = httpConfig.release();
  context_.httpContext->confB  = context_.httpContext->conf;
  context_.httpContext->parent = context_.globalContext;

  context_.serverContext         = new ServerContext();
  context_.serverContext->conf   = serverConfig.release();
  context_.serverContext->confB  = context_.serverContext->conf;
  context_.serverContext->parent = context_.httpContext;

  context_.locationContext         = new LocationContext();
  context_.locationContext->conf   = locationConfig.release();
  context_.locationContext->confB  = context_.locationContext->conf;
  context_.locationContext->parent = context_.serverContext;

  context_.now = kGlobalOffset;
}

ConfigManager::~ConfigManager() {
  delete context_.globalContext->conf;
  delete context_.httpContext->conf;
  delete context_.serverContext->conf;
  delete context_.locationContext->conf;
  delete context_.globalContext;
  delete context_.httpContext;
  delete context_.serverContext;
  delete context_.locationContext;
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

void server::ConfigManager::configParse(const char *data, const size_t len) {
  if (len <= 0) {
    LOG_FATAL("Data length cannot be non-positive! Input length: " + std::to_string(len));
    throw std::invalid_argument("Invalid data length");
  }

  std::string word;
  std::vector<std::string> wordVector;
  bool inComment = false;

  LOG_INFO("Starting configuration parsing");

  for (size_t i = 0; i < len; ++i) {
    if (data[i] == '#') {
      inComment = true;
      word.clear();
      continue;
    }

    if (data[i] == '\n') {
      inComment = false;
      continue;
    }

    if (inComment) {
      continue;
    }

    if (std::isspace(data[i]) != 0) {
      if (!word.empty()) {
        LOG_INFO("Found word: " + word);
        wordVector.push_back(word);
        word.clear();
      }
      continue;
    }

    if (data[i] == '{') {
      if (!word.empty()) {
        LOG_INFO("Found block start: " + word);
        wordVector.push_back(word);
        word.clear();
      }
      handleCommand(wordVector);
      wordVector.clear();
      continue;
    }

    if (data[i] == ';') {
      if (!word.empty()) {
        wordVector.push_back(word);
        word.clear();
      }
      if (!wordVector.empty()) {
        LOG_INFO("Handling command: " + wordVector[0]);
        handleCommand(wordVector);
        wordVector.clear();
      }
      continue;
    }

    if (data[i] == '}') {
      if (!word.empty()) {
        wordVector.push_back(word);
        word.clear();
      }
      if (!wordVector.empty()) {
        handleCommand(wordVector);
        wordVector.clear();
      }
      LOG_INFO("Found block end");
      bool result = setParentContext(context_);
      if (result) {
        continue;
      }
      continue;
    }

    word += data[i];
  }

  LOG_INFO("Configuration parsing completed");
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

    bool validArgs = field.empty() ? (expectedArgs == 0) : (field.size() == expectedArgs);
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

  LOG_INFO("Current context: " + std::to_string(context_.now));
  LOG_INFO("Command offset: " + std::to_string(cmd.confOffset));

  if (cmd.confOffset != 0U) {
    context_.now = cmd.confOffset;
    LOG_INFO("Switching to context: " + std::to_string(context_.now));
  }

  if (cmd.set) {
    cmd.set(field, getContextByOffset(context_.now), it->second.offset);
  }

  if (valueType == 0) {
    return;
  }

  try {
    auto *ctx = getConfigByOffset(context_.now);
    if (ctx == nullptr) {
      throw std::runtime_error("Invalid configuration context");
    }
    char *base = reinterpret_cast<char *>(ctx);

    LOG_INFO("Base pointer: " + std::to_string(reinterpret_cast<uintptr_t>(base)));
    LOG_INFO("Config offset: " + std::to_string(cmd.offset));
    LOG_INFO("Value type: " + std::to_string(static_cast<int>(valueType)));

    switch (valueType) {
      case static_cast<uint32_t>(CommandType::configFlag): {
        bool *target = reinterpret_cast<bool *>(base + cmd.offset);
        LOG_INFO(
            "Setting bool value at address: " + std::to_string(reinterpret_cast<uintptr_t>(target))
        );
        *target = (field[0] == "on" || field[0] == "true" || field[0] == "1");
        break;
      }

      case static_cast<uint32_t>(CommandType::configNumber): {
        int *target = reinterpret_cast<int *>(base + cmd.offset);
        LOG_INFO(
            "Setting int value at address: " + std::to_string(reinterpret_cast<uintptr_t>(target))
        );
        *target = std::stoi(field[0]);
        break;
      }

      case static_cast<uint32_t>(CommandType::configString): {
        auto *target = reinterpret_cast<std::string *>(base + cmd.offset);
        LOG_INFO(
            "Setting string value at address: "
            + std::to_string(reinterpret_cast<uintptr_t>(target))
        );
        *target = field[0];
        break;
      }

      case static_cast<uint32_t>(CommandType::configSizeT): {
        auto *target = reinterpret_cast<size_t *>(base + cmd.offset);
        LOG_INFO(
            "Setting size_t value at address: "
            + std::to_string(reinterpret_cast<uintptr_t>(target))
        );
        *target = std::stoull(field[0]);
        break;
      }

      default:
        LOG_FATAL("No matching type!");
        throw std::invalid_argument("No matching type!");
    }

  } catch (const std::exception &e) {
    LOG_FATAL(e.what());
    throw;
  }
}

void *ConfigManager::getContextByOffset(size_t offset) {
  if (offset != kGlobalOffset && offset != kHttpOffset && offset != kServerOffset
      && offset != kLocationOffset) {
    throw std::out_of_range("Invalid context offset");
  }

  std::cout << ("Getting context for offset: " + std::to_string(offset)) << '\n';
  std::cout << ("Current context now: " + std::to_string(context_.now)) << '\n';

  char *base = reinterpret_cast<char *>(&context_);
  void **ptr = reinterpret_cast<void **>(base + offset);

  if (*ptr == nullptr) {
    throw std::runtime_error("Null context pointer");
  }

  std::cout
      << ("Context pointer before dereference: " + std::to_string(reinterpret_cast<uintptr_t>(ptr)))
      << '\n';
  std::cout << ("Context value at pointer: " + std::to_string(reinterpret_cast<uintptr_t>(*ptr)))
            << '\n';

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
    handleLocationEnd(context.locationContext);
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

void *ConfigManager::getConfigByOffset(size_t offset) {
  auto *ctx = static_cast<ContextBase *>(getContextByOffset(offset));
  if ((ctx == nullptr) || (ctx->confB == nullptr)) {
    throw std::runtime_error("Invalid configuration pointer");
  }
  return ctx->confB;
}

void ConfigManager::handleLocationEnd(LocationContext *ctx) {
  auto &router = Router::getInstance();
  router.addRoute(*ctx->conf);

  *ctx->conf = LocationConfig();
}
} // namespace server
