#include "include/config_commands.h"
#include "include/main_application.h"
#include "include/ssl_manager.h"
#include "server/include/config_manager.h"
#include "server/include/log.h"
#include "server/include/router.h"

#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>

using namespace server;

int main(int argc, char *argv[]) {
  try {
    LOG_INFO("Server starting up");
    LOG_INFO("Process ID: " + std::to_string(getpid()));

    std::filesystem::path projectRoot = std::filesystem::current_path();
    std::filesystem::path configPath  = projectRoot / "conf" / "config";

    LOG_INFO("Project root: " + projectRoot.string());

    MainApplication::createAutoConfig(projectRoot);

    LOG_TRACE("Initializing Router MIME types");
    server::Router::initializeMime();

    EventLoop mainLoop;
    auto mainApplication = std::make_shared<MainApplication>();

    mainApplication->initSignalHandlers(&mainLoop);

    ConfigManager &configManager = ConfigManager::getInstance();
    configManager.registerCommands(getAllCommands());
    server::ConfigManager::setServerCallback([mainApplication](const ServerConfig &conf) {
      mainApplication->addServer(conf);
    });

    std::string context = MainApplication::loadConfig(configPath);

    configManager.configParse(context.c_str(), context.length());

    mainApplication->handleParam(argc, argv);

    mainApplication->startAllServers();
    mainLoop.loop();
    mainApplication->stopAll();

    return 0;
  } catch (const std::exception &e) {
    LOG_FATAL("Fatal error occurred: " + std::string(e.what()));
    std::cerr << "Fatal error: " << e.what() << '\n';
    return 1;
  }
}
