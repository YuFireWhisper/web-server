#include "include/main_application.h"

#include "include/event_loop.h"
#include "include/event_loop_thread.h"
#include "include/http_server.h"
#include "include/inet_address.h"

#include <csignal>

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
  std::vector<ServerConfig> configs;
  {
    std::lock_guard lock(serverMutex_);
    configs = std::move(pendingConfigs_);
    pendingConfigs_.clear();
  }

  for (const auto &config : configs) {
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

} // namespace server
