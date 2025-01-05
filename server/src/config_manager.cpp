#include "include/config_manager.h"

#include "include/config_defaults.h"
#include "include/event_loop.h"
#include "include/http_server.h"
#include "include/inet_address.h"
#include "include/log.h"
#include "include/router.h"
#include "include/ssl_manager.h"
#include "include/types.h"

#include <cctype>
#include <cstring>

namespace server {

namespace {
constexpr size_t GLOBAL_CTX   = offsetof(ConfigContext, globalContext);
constexpr size_t HTTP_CTX     = offsetof(ConfigContext, httpContext);
constexpr size_t SERVER_CTX   = offsetof(ConfigContext, serverContext);
constexpr size_t LOCATION_CTX = offsetof(ConfigContext, locationContext);

constexpr uint32_t FIXED_ARG_MASK = static_cast<uint32_t>(CommandType::configNoArgs)
                                    | static_cast<uint32_t>(CommandType::configTake1)
                                    | static_cast<uint32_t>(CommandType::configTake2)
                                    | static_cast<uint32_t>(CommandType::configTake3);
} // namespace

ConfigManager &ConfigManager::getInstance() {
  static ConfigManager instance;
  return instance;
}

ConfigManager::ConfigManager()
    : context_() {
  context_.globalContext        = new GlobalContext();
  context_.globalContext->conf  = new GlobalConfig();
  context_.globalContext->confB = context_.globalContext->conf;

  context_.httpContext         = new HttpContext();
  context_.httpContext->conf   = new HttpConfig();
  context_.httpContext->confB  = context_.httpContext->conf;
  context_.httpContext->parent = context_.globalContext;

  context_.serverContext         = new ServerContext();
  context_.serverContext->conf   = new ServerConfig();
  context_.serverContext->confB  = context_.serverContext->conf;
  context_.serverContext->parent = context_.httpContext;

  context_.locationContext         = new LocationContext();
  context_.locationContext->conf   = new LocationConfig();
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
  commands_.emplace(cmd.name, cmd);
}

void ConfigManager::registerCommands(const std::vector<ServerCommand> &cmds) {
  commands_.reserve(commands_.size() + cmds.size());
  for (const auto &cmd : cmds) {
    registerCommand(cmd);
  }
}

void ConfigManager::processComment(const char *data, size_t len, size_t &pos) {
  const char *newline = std::strchr(data + pos, '\n');
  pos                 = (newline != nullptr) ? (newline - data) : len;
}

void ConfigManager::processBlockStart(std::string &word, std::vector<std::string> &words) {
  if (!word.empty()) {
    words.push_back(std::move(word));
    word.clear();
  }
  if (!words.empty()) {
    handleCommand(std::move(words));
    words.clear();
  }
}

void ConfigManager::processBlockEnd(std::string &word, std::vector<std::string> &words) {
  if (!word.empty()) {
    words.push_back(std::move(word));
    word.clear();
  }
  if (!words.empty()) {
    handleCommand(std::move(words));
    words.clear();
  }
  if (!setParentContext(context_)) {
    throw std::runtime_error("Invalid block nesting");
  }
}

void ConfigManager::processCharacter(char c, std::string &word) {
  if (std::isspace(static_cast<unsigned char>(c)) != 0) {
    return;
  }
  word += c;
}

void ConfigManager::configParse(const char *data, const size_t len) {
  if (len == 0) {
    throw std::invalid_argument("Empty configuration data");
  }

  std::string word;
  std::vector<std::string> words;
  words.reserve(8);

  for (size_t i = 0; i < len; ++i) {
    const char c = data[i];

    if (c == '#' && i + 1 < len) {
      processComment(data, len, i);
      continue;
    }

    if (std::isspace(static_cast<unsigned char>(c)) != 0) {
      if (!word.empty()) {
        words.push_back(std::move(word));
        word.clear();
      }
      continue;
    }

    switch (c) {
      case '{':
        processBlockStart(word, words);
        break;

      case '}':
        processBlockEnd(word, words);
        break;

      case ';':
        if (!word.empty()) {
          words.push_back(std::move(word));
          word.clear();
        }
        if (!words.empty()) {
          handleCommand(std::move(words));
          words.clear();
        }
        break;

      default:
        processCharacter(c, word);
        break;
    }
  }
}

uint32_t ConfigManager::getCommandArgBits(CommandType type) {
  const auto typeValue = static_cast<uint32_t>(type);
  return typeValue & argsMask;
}

bool ConfigManager::validateCommandArgs(CommandType type, size_t argCount) {
  const auto typeValue = static_cast<uint32_t>(type);

  if ((typeValue & static_cast<uint32_t>(CommandType::config2more)) != 0U) {
    return argCount >= 2;
  }

  if ((typeValue & static_cast<uint32_t>(CommandType::config1more)) != 0U) {
    return argCount >= 1;
  }

  if ((typeValue & FIXED_ARG_MASK) != 0U) {
    switch (getCommandArgBits(type)) {
      case static_cast<uint32_t>(CommandType::configNoArgs):
        return argCount == 0;
      case static_cast<uint32_t>(CommandType::configTake1):
        return argCount == 1;
      case static_cast<uint32_t>(CommandType::configTake2):
        return argCount == 2;
      case static_cast<uint32_t>(CommandType::configTake3):
        return argCount == 3;
      default:
        return false;
    }
  }

  return false;
}

void ConfigManager::handleCommand(std::vector<std::string> field) {
  if (field.empty()) {
    throw std::invalid_argument("Empty command field");
  }

  const auto cmdIt = commands_.find(field[0]);
  if (cmdIt == commands_.end()) {
    throw std::invalid_argument("Unknown command: " + field[0]);
  }

  LOG_DEBUG("Processing command: " + cmdIt->first);
  for (const auto &arg : field) {
    LOG_DEBUG("Argument: " + arg);
  }

  field.erase(field.begin());
  const auto &cmd = cmdIt->second;

  if (!hasCommandFlag(getContextType(&context_), cmd.type)) {
    throw std::invalid_argument("Invalid command context");
  }

  if (!validateCommandArgs(cmd.type, field.size())) {
    throw std::invalid_argument("Invalid argument count for command: " + cmdIt->first);
  }

  if (cmd.confOffset != 0) {
    LOG_DEBUG("Setting configuration context: " + std::to_string(cmd.confOffset));
    context_.now = cmd.confOffset;
  }

  processCommandField(field, cmd);
}

void ConfigManager::processCommandField(
    const std::vector<std::string> &field,
    const ServerCommand &cmd
) const {
  if (cmd.set != nullptr) {
    cmd.set(field, getContextByOffset(context_.now), cmd.offset);
    return;
  }

  const uint32_t valueType = static_cast<uint32_t>(cmd.type) & typeMask;
  if (valueType == 0) {
    return;
  }

  auto *config = getConfigByOffset(context_.now);
  if (config == nullptr) {
    throw std::runtime_error("Invalid configuration context");
  }

  updateConfigValue(config, cmd, field[0]);
}

void ConfigManager::updateConfigValue(
    void *basePtr,
    const ServerCommand &cmd,
    const std::string &value
) {
  const uint32_t valueType = static_cast<uint32_t>(cmd.type) & typeMask;
  auto *base               = static_cast<char *>(basePtr);

  switch (valueType) {
    case static_cast<uint32_t>(CommandType::configFlag): {
      auto *target = reinterpret_cast<bool *>(base + cmd.offset);
      *target      = (value == "on" || value == "true" || value == "1");
      break;
    }
    case static_cast<uint32_t>(CommandType::configNumber): {
      auto *target = reinterpret_cast<int *>(base + cmd.offset);
      *target      = std::stoi(value);
      break;
    }
    case static_cast<uint32_t>(CommandType::configString): {
      auto *target = reinterpret_cast<std::string *>(base + cmd.offset);
      *target      = value;
      LOG_DEBUG("Setting string value: " + *target);
      break;
    }
    case static_cast<uint32_t>(CommandType::configSizeT): {
      auto *target = reinterpret_cast<size_t *>(base + cmd.offset);
      *target      = std::stoull(value);
      break;
    }
    default:
      throw std::invalid_argument("Invalid value type");
  }
}

void *ConfigManager::getContextByOffset(size_t offset) const {
  if (offset == GLOBAL_CTX) {
    return context_.globalContext;
  }
  if (offset == HTTP_CTX) {
    return context_.httpContext;
  }
  if (offset == SERVER_CTX) {
    return context_.serverContext;
  }
  if (offset == LOCATION_CTX) {
    return context_.locationContext;
  }
  throw std::out_of_range("Invalid context offset");
}

CommandType ConfigManager::getContextType(ConfigContext *context) const {
  auto *ctx = static_cast<ContextBase *>(getContextByOffset(context->now));
  return ctx != nullptr ? ctx->typeB : throw std::runtime_error("Invalid context");
}

bool ConfigManager::hasCommandFlag(CommandType input, CommandType flag) {
  return (static_cast<uint32_t>(input) & static_cast<uint32_t>(flag)) != 0;
}

bool ConfigManager::setParentContext(ConfigContext &context) {
  switch (static_cast<uint32_t>(context.now)) {
    case LOCATION_CTX:
      handleLocationEnd(context.locationContext);
      context.now = kServerOffset;
      return true;
    case SERVER_CTX:
      handleServerEnd(context.serverContext);
      context.now = kHttpOffset;
      return true;
    case HTTP_CTX:
      context.now = kGlobalOffset;
      return true;
    default:
      return false;
  }
}

ConfigContext &ConfigManager::getCurrentContext() {
  return context_;
}

void ConfigManager::setCurrentContext(const ConfigContext &context) {
  context_ = context;
}

void *ConfigManager::getConfigByOffset(size_t offset) const {
  auto *ctx = static_cast<ContextBase *>(getContextByOffset(offset));
  return ctx != nullptr ? ctx->confB : nullptr;
}

void ConfigManager::handleLocationEnd(LocationContext *ctx) {
  auto &router = Router::getInstance();
  router.addRoute(*ctx->conf);
  *ctx->conf = LocationConfig();
}

void ConfigManager::handleServerEnd(ServerContext *ctx) {
  auto *conf = ctx->conf;

  SSLManager::getInstance().addServer(*conf);

  EventLoop loop;
  InetAddress addr(conf->AddressFamily, conf->address, conf->port);
  HttpServer server(&loop, addr, *conf);
  *ctx->conf = ServerConfig();
  server.start();
  loop.loop();
}
} // namespace server
