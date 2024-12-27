#include "include/config_commands.h"
#include "include/config_defaults.h"
#include "server/include/config_manager.h"
#include "server/include/http_server.h"
#include "server/include/inet_address.h"
#include "server/include/log.h"
#include "server/include/router.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <system_error>

namespace fs = std::filesystem;

using namespace server;

void createAutoConfig(const fs::path &projectRoot) {
  LOG_INFO("Starting auto configuration creation");

  fs::path autoDir = projectRoot / "server" / "auto";
  std::error_code ec;

  LOG_INFO("Creating auto directory at: " + autoDir.string());
  fs::create_directories(autoDir, ec);
  if (ec) {
    LOG_ERROR("Failed to create auto directory: " + ec.message());
    throw std::runtime_error("Failed to create auto directory: " + ec.message());
  }

  fs::path autoConfigPath = autoDir / "auto_config.h";

  LOG_INFO("Removing existing auto_config if present");
  fs::remove(autoConfigPath, ec);
  if (ec) {
    LOG_ERROR("Failed to remove existing auto_config.h: " + ec.message());
    throw std::runtime_error("Failed to remove existing auto_config.h: " + ec.message());
  }

  LOG_INFO("Creating new auto_config.h at: " + autoConfigPath.string());
  std::ofstream autoConfig(autoConfigPath);
  if (!autoConfig) {
    LOG_ERROR("Failed to create auto_config.h");
    throw std::runtime_error("Failed to create auto_config.h");
  }

  autoConfig << "#pragma once\n";
  autoConfig << "#define kPorjectRoot \"" << projectRoot.string() << "/\"\n";
  autoConfig.close();

  LOG_INFO("Auto configuration created successfully");
}

void loadConfig(const fs::path &configPath) {
  LOG_INFO("Attempting to load configuration from: " + configPath.string());

  std::ifstream configFile(configPath, std::ios::binary);
  if (!configFile) {
    LOG_INFO("No configuration file found, using default settings");
    return;
  }

  LOG_INFO("Reading configuration file contents");
  std::string content(
      (std::istreambuf_iterator<char>(configFile)),
      std::istreambuf_iterator<char>()
  );
  configFile.close();

  LOG_INFO("Configuration file size: " + std::to_string(content.length()) + " bytes");

  try {
    LOG_INFO("Parsing configuration file");
    auto &configManager = server::ConfigManager::getInstance();
    configManager.registerCommands(getAllCommands());
    configManager.configParse(content.c_str(), content.length());
    LOG_INFO("Configuration parsed successfully");
  } catch (const std::exception &e) {
    LOG_ERROR("Configuration parsing failed: " + std::string(e.what()));
    throw;
  }
}

int main(int argc, char *argv[]) {
  try {
    LOG_INFO("Server starting up");
    LOG_INFO("Process ID: " + std::to_string(getpid()));

    fs::path projectRoot = fs::current_path();
    LOG_INFO("Project root: " + projectRoot.string());

    createAutoConfig(projectRoot);

    LOG_INFO("Initializing Router MIME types");
    server::Router::initializeMime();

    fs::path configPath;
    if (argc > 1) {
      configPath = argv[1];
      LOG_INFO("Using custom config path: " + std::string(argv[1]));
    } else {
      configPath = projectRoot / "conf" / "config";
      LOG_INFO("Using default config path: " + configPath.string());
    }

    loadConfig(configPath);

    LOG_INFO("Retrieving server configuration");
    auto &configManager = server::ConfigManager::getInstance();
    auto *serverContext =
        static_cast<server::ServerContext *>(configManager.getContextByOffset(server::kServerOffset)
        );

    if ((serverContext == nullptr) || (serverContext->conf == nullptr)) {
      LOG_ERROR("Failed to get server configuration");
      return 1;
    }

    LOG_INFO("Creating event loop");
    server::EventLoop loop;

    LOG_INFO("Setting up listen address");
    // server::InetAddress listenAddr(
    //     serverContext->conf->AddressFamily,
    //     serverContext->conf->ip,
    //     serverContext->conf->port
    // );

    // LOG_INFO("Creating HTTP server instance");
    // server::HttpServer server(&loop, listenAddr, "MyServer");
    //
    // LOG_INFO("Starting server on " + listenAddr.getIpPort());
    // server.start();

    LOG_INFO("Entering main event loop");
    loop.loop();

    return 0;
  } catch (const std::exception &e) {
    LOG_FATAL("Fatal error occurred: " + std::string(e.what()));
    std::cerr << "Fatal error: " << e.what() << '\n';
    return 1;
  }
}
