#include "include/acme_client.h"
#include "include/config_commands.h"
#include "include/main_application.h"
#include "include/ssl_manager.h"
#include "server/include/config_manager.h"
#include "server/include/log.h"
#include "server/include/router.h"

#include <csignal>
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
  autoConfig << "#define kProjectRoot \"" << projectRoot.string() << "/\"\n";
  autoConfig.close();

  LOG_INFO("Auto configuration created successfully");
}

std::string loadConfig(const fs::path &configPath) {
  LOG_INFO("Attempting to load configuration from: " + configPath.string());

  std::ifstream configFile(configPath, std::ios::binary);
  if (!configFile) {
    LOG_INFO("No configuration file found, using default settings");
    return "";
  }

  LOG_INFO("Reading configuration file contents");
  std::string content(
      (std::istreambuf_iterator<char>(configFile)),
      std::istreambuf_iterator<char>()
  );
  configFile.close();

  LOG_INFO("Configuration file size: " + std::to_string(content.length()) + " bytes");

  return content;
}

void printUsage(const char *programName) {
  LOG_INFO("Usage:");
  LOG_INFO(programName + std::string(" [config_path]"));
  LOG_INFO(programName + std::string(" --finalize"));
  LOG_INFO("Options:");
  LOG_INFO("[config_path]  : Path to configuration file (optional)");
  LOG_INFO("--finalize     : Execute ACME certificate finalization");
}

void handleSignal(int sig, EventLoop *mainLoop, const std::shared_ptr<MainApplication> &app) {
  LOG_INFO("Received signal: " + std::to_string(sig));

  if (app) {
    LOG_INFO("Stopping all servers...");
    app->stopAll();
  }

  if (mainLoop != nullptr) {
    LOG_INFO("Quitting main event loop...");
    mainLoop->quit();
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

    fs::path configPath = projectRoot / "conf" / "config";

    EventLoop mainLoop;
    auto mainApplication = std::make_shared<MainApplication>();

    mainApplication->initSignalHandlers(&mainLoop);

    ConfigManager &configManager = ConfigManager::getInstance();
    configManager.registerCommands(getAllCommands());
    server::ConfigManager::setServerCallback([mainApplication](const ServerConfig &conf) {
      mainApplication->addServer(conf);
    });

    std::string context = loadConfig(configPath);
    configManager.configParse(context.c_str(), context.length());

    if (argc > 1 && std::string(argv[1]) != "--finalize") {
      LOG_INFO("Loading configuration from command line argument");
      context = loadConfig(argv[1]);
      configManager.configParse(context.c_str(), context.length());
    }

    if (argc > 1 && std::string(argv[1]) == "--finalize") {
      int result = 0;

      if (argc < 4) {
        LOG_ERROR("Usage: " + std::string(argv[0]) + " --finalize <server-name> <challenge-type>");
        result = 1;
      } else {
        std::string serverName    = argv[2];
        std::string challengeType = argv[3];

        if (challengeType != "dns-01" && challengeType != "http-01") {
          LOG_ERROR("Invalid challenge type. Supported types: dns-01, http-01");
          result = 1;
        } else {
          LOG_INFO("Executing ACME certificate finalization with " + challengeType);
          loadConfig(projectRoot / "conf" / "config");

          try {
            int validationResult =
                SSLManager::getInstance().validateChallenge(serverName, challengeType);

            switch (validationResult) {
              case NEED_RECREATE_CERTIFICATE:
                LOG_INFO("Certificate needs to be recreated");
                LOG_INFO("Please restart program, it will automatically recreate the certificate");
                result = 0;
                break;

              case CERTIFICATE_PROCESSING:
                LOG_INFO("Certificate is still processing");
                result = 0;
                break;

              case CERTIFICATE_CREATE_SUCCESS:
                LOG_INFO("Certificate created successfully");
                LOG_INFO("Please restart program to use the new certificate");
                result = 0;
                break;

              default:
                LOG_ERROR("Unknown validation result");
                result = 1;
                break;
            }
          } catch (const std::exception &e) {
            LOG_ERROR("Certificate finalization failed: " + std::string(e.what()));
            result = 1;
          }
        }
      }

      return result;
    }

    LOG_INFO("Starting all servers...");
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
