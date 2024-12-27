#pragma once

#include "auto/auto_config.h"
#include "include/types.h"

#include <cstddef>
#include <filesystem>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>

#define OFFSET_OF(type, member)                                                                    \
  (reinterpret_cast<size_t>(&reinterpret_cast<char const volatile &>(((type *)0)->member)))

namespace server {

struct GlobalConfig {
  std::string systemLogPath = std::string(kPorjectRoot) + "logs/system.log";
  int timerCheckInterval    = 100;
  size_t maxTimers          = 10000;
  int pollTimeoutMs         = 10000;
  size_t maxEvents          = 4096;
  size_t threadNum          = std::thread::hardware_concurrency();
};

struct HttpConfig {
  size_t maxHeaderSize                    = kKib * 8;
  size_t maxBodySize                      = kMib;
  size_t keepAliveTimeout                 = 60;
  std::string serverName                  = "MyServer";
  std::vector<std::string> allowedMethods = { "GET", "POST", "HEAD" };
  size_t initialBufferSize                = kKib;
  size_t maxBufferSize                    = kMib * 64;
  size_t extraBufferSize                  = kKib * 64;
  size_t prependSize                      = 8;
  size_t highWaterMark                    = kDefaultHighWaterMark;
};

struct ServerConfig {
  short AddressFamily   = AF_INET;
  std::string ip        = "0.0.0.0";
  in_port_t port        = 8080;
  bool reusePort        = false;
  bool tcpNoDelay       = true;
  bool keepAlive        = true;
  int keepAliveIdle     = 60;
  int keepAliveInterval = 30;
  int keepAliveCount    = 3;
};

struct LocationConfig {
  std::string name = "/";
  Method method    = Method::kInvalid;
  std::filesystem::path staticFile;
  std::filesystem::path rootPath;
  std::string proxyPath;
  std::unordered_map<std::string, std::shared_ptr<LocationConfig>> children;
  RouteHandler handler;
};

struct ContextBase {
  CommandType typeB;
  void *confB;
};

struct GlobalContext : public ContextBase {
  GlobalConfig *conf;
  GlobalContext() {
    typeB = CommandType::global;
    confB = conf;
  }
};

struct HttpContext : public ContextBase {
  HttpConfig *conf;
  GlobalContext *parent;
  HttpContext() {
    typeB = CommandType::http;
    confB = conf;
  }
};

struct ServerContext : public ContextBase {
  ServerConfig *conf;
  HttpContext *parent;
  ServerContext() {
    typeB = CommandType::server;
    confB = conf;
  }
};

struct LocationContext : public ContextBase {
  LocationConfig *conf;
  ServerContext *parent;
  LocationContext() {
    typeB = CommandType::location;
    confB = conf;
  }
};

struct ConfigContext {
  GlobalContext *globalContext;
  HttpContext *httpContext;
  ServerContext *serverContext;
  LocationContext *locationContext;
  size_t now;
};

const size_t kGlobalOffset   = OFFSET_OF(ConfigContext, globalContext);
const size_t kHttpOffset     = OFFSET_OF(ConfigContext, httpContext);
const size_t kServerOffset   = OFFSET_OF(ConfigContext, serverContext);
const size_t kLocationOffset = OFFSET_OF(ConfigContext, locationContext);
} // namespace server
