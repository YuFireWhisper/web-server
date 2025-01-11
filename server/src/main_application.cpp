#include "include/main_application.h"

#include "include/acme_client.h"
#include "include/event_loop.h"
#include "include/event_loop_thread.h"
#include "include/file_system.h"
#include "include/http_server.h"
#include "include/inet_address.h"
#include "include/ssl_manager.h"

#include <csignal>
#include <fstream>

namespace {
constexpr int FINALIZE_NEED_PARAM_NUM = 4;
}

namespace server {

MainApplication *MainApplication::instance_ = nullptr;

MainApplication::~MainApplication() {
  stopAll();
  if (instance_ == this) {
    instance_ = nullptr;
  }
}

void MainApplication::addServer(const ServerConfig &config) {
  std::lock_guard lock(serverMutex_);
  pendingConfigs_.push_back(config);
}

void MainApplication::stopAll() {
  std::vector<std::shared_ptr<HttpServer>> serversToStop;
  std::vector<std::shared_ptr<EventLoopThread>> threadsToStop;

  {
    std::lock_guard lock(serverMutex_);
    serversToStop = servers_;
    threadsToStop = threads_;
  }

  for (auto &server : serversToStop) {
    auto *loop = server->getLoop();
    if (loop->isInLoopThread()) {
      server->stop();
    } else {
      loop->runInLoop([server]() { server->stop(); });
    }
  }

  for (auto &thread : threadsToStop) {
    thread->stop();
  }

  {
    std::lock_guard lock(serverMutex_);
    servers_.clear();
    threads_.clear();
  }
}

void MainApplication::startAllServers() {
  LOG_TRACE("===== Starting all servers =====");
  std::vector<ServerConfig> configs;
  {
    std::lock_guard lock(serverMutex_);
    configs = std::move(pendingConfigs_);
    pendingConfigs_.clear();
  }

  for (const auto &config : configs) {
    LOG_TRACE("Starting server: " + config.serverName);

    auto thread = std::make_shared<EventLoopThread>();
    auto *loop  = thread->startLoop();

    loop->runInLoop([this, loop, config, thread]() mutable {
      auto server = std::make_shared<HttpServer>(
          loop,
          InetAddress(config.AddressFamily, config.address, config.port),
          config
      );

      server->start();

      std::lock_guard lock(serverMutex_);
      servers_.emplace_back(std::move(server));
      threads_.emplace_back(std::move(thread));
    });
  }

  LOG_TRACE("===== All servers started =====");
}

void MainApplication::initSignalHandlers(EventLoop *mainLoop) {
  mainLoop_ = mainLoop;
  instance_ = this;

  signal(SIGINT, handleSignal);
  signal(SIGTERM, handleSignal);
}

void MainApplication::handleSignal(int sig) {
  LOG_INFO("Received signal: " + std::to_string(sig));

  if (instance_ != nullptr) {
    LOG_INFO("Stopping all servers...");
    instance_->stopAll();

    if (instance_->mainLoop_ != nullptr) {
      LOG_INFO("Quitting main event loop...");
      instance_->mainLoop_->quit();
    }
  }
}

void MainApplication::initParamHandlers() {
  paramHandlers_["--help"]     = [this]() { return handleHelp(); };
  paramHandlers_["--finalize"] = [this]() { return handleFinalize(); };
}

int MainApplication::handleParam(int argc, char *argv[]) {
  LOG_TRACE("===== Starting parameter parsing =====");
  if (argc <= 1) {
    LOG_TRACE("No Parameter");
    LOG_TRACE("===== Parameter parsing complete =====");
    return 2;
  }

  argc_ = argc;
  argv_.reserve(argc);
  for (int i = 0; i < argc; ++i) {
    argv_.emplace_back(argv[i]);
  }

  initParamHandlers();

  auto it = paramHandlers_.find(argv[1]);
  if (it == paramHandlers_.end()) {
    LOG_ERROR("Unknown parameter: " + std::string(argv[1]));
    return 1;
  }

  int ret = it->second();
  LOG_TRACE("===== Finished parameter parsing =====");

  return ret;
}

int MainApplication::handleHelp() {
  LOG_INFO("Usage: " + argv_[0] + " [options]");
  LOG_INFO("Options:");
  LOG_INFO("  --help     Display this help message");
  LOG_INFO("  --finalize Finalize ACME certificate generation");
  return 0;
}

int MainApplication::handleFinalize() {
  if (argc_ != FINALIZE_NEED_PARAM_NUM) {
    LOG_ERROR("Invalid number of parameters");
    LOG_ERROR("Usage: " + argv_[0] + " --finalize <server-name> <challenge-type>");
    return 1;
  }

  std::string serverName    = argv_[2];
  std::string challengeType = argv_[3];

  if (challengeType != "dns-01" && challengeType != "http-01") {
    LOG_ERROR("Invalid challenge type. Supported types: dns-01, http-01");
    return 1;
  }

  int ret = SSLManager::getInstance().validateChallenge(serverName, challengeType);
  switch (ret) {
    case NEED_RECREATE_CERTIFICATE:
      LOG_INFO("Certificate needs to be recreated");
      LOG_INFO("Please restart program, it will automatically recreate the certificate");
      return 0;
    case CERTIFICATE_PROCESSING:
      LOG_INFO("Certificate is still processing");
      LOG_INFO("Please wait, it will take some time");
      return 0;
    case CERTIFICATE_CREATE_SUCCESS:
      LOG_INFO("Certificate created successfully");
      LOG_INFO("Please restart program to use the new certificate");
      return 0;
    default:
      LOG_ERROR("Unknown validation result");
      return 1;
  };
}

void MainApplication::createAutoConfig(const std::filesystem::path &projectRoot) {
  std::filesystem::path autoDir = projectRoot / "server" / "auto";
  std::error_code ec;

  std::filesystem::create_directories(autoDir, ec);
  if (ec) {
    LOG_ERROR("Failed to create auto directory: " + ec.message());
    throw std::runtime_error("Failed to create auto directory: " + ec.message());
  }

  std::filesystem::path autoConfigPath = autoDir / "auto_config.h";
  std::filesystem::remove(autoConfigPath, ec);
  if (ec) {
    LOG_ERROR("Failed to remove existing auto_config.h: " + ec.message());
    throw std::runtime_error("Failed to remove existing auto_config.h: " + ec.message());
  }

  std::ofstream autoConfig(autoConfigPath);
  if (!autoConfig) {
    LOG_ERROR("Failed to create auto_config.h");
    throw std::runtime_error("Failed to create auto_config.h");
  }

  autoConfig << "#pragma once\n";
  autoConfig << "#define kProjectRoot \"" << projectRoot.string() << "/\"\n";
  autoConfig.close();

  LOG_INFO << "Auto configuration created";
  LOG_INFO << "Auto Directory Name: " << GET_FILE_NAME(autoDir.string());
  LOG_INFO << "Auto Config File Name: " << GET_FILE_NAME(autoConfigPath.string());
}

std::string MainApplication::loadConfig(const std::filesystem::path &configPath) {
  std::ifstream configFile(configPath, std::ios::binary);

  if (!configFile) {
    LOG_INFO << "Configuration file not found";
    return "";
  }

  std::string content(
      (std::istreambuf_iterator<char>(configFile)),
      std::istreambuf_iterator<char>()
  );
  configFile.close();

  LOG_INFO << "Configuration file loaded";
  LOG_INFO << "Configuration File Name: " << GET_FILE_NAME(configPath.string());
  LOG_INFO << "Configuration File Size: " << content.size();

  return content;
}

} // namespace server
