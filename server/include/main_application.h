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

  void startAllServers();
  void stopAll();

  void initSignalHandlers(EventLoop *mainLoop);
  static void handleSignal(int sig);

  int handleParam(int argc, char *argv[]);
  int handleHelp();
  int handleFinalize();

  static void createAutoConfig(const std::filesystem::path &projectRoot);
  static std::string loadConfig(const std::filesystem::path &configPath); 

private:
  void initParamHandlers();

  std::mutex serverMutex_;
  std::vector<std::shared_ptr<HttpServer>> servers_;
  std::vector<std::shared_ptr<EventLoopThread>> threads_;
  std::vector<ServerConfig> pendingConfigs_;
  int argc_ = 0;
  std::vector<std::string> argv_;
  inline static std::unordered_map<std::string, std::function<int()>> paramHandlers_;
  
  EventLoop *mainLoop_ = nullptr;
  static MainApplication *instance_;
};
} // namespace server
