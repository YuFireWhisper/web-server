#pragma once

#include "include/config_defaults.h"

namespace server {

class HttpServer;
class EventLoopThread;

class MainApplication {
public:
  MainApplication() = default;
  ~MainApplication();

  void addServer(const ServerConfig &config);
  void stopAll();

  void startAllServers();

  void initSignalHandlers(EventLoop *mainLoop);
  static void handleSignal(int sig);

private:
  std::mutex serverMutex_;
  std::vector<std::shared_ptr<HttpServer>> servers_;
  std::vector<std::shared_ptr<EventLoopThread>> threads_;
  std::vector<ServerConfig> pendingConfigs_;

  EventLoop *mainLoop_ = nullptr;
  static MainApplication *instance_;
};
} // namespace server
