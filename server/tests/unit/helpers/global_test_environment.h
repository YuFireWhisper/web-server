#include "include/config_manager.h"

#include <gtest/gtest.h>

namespace server::testing {

class GlobalTestEnvironment : public ::testing::Environment {
public:
  void SetUp() override { initialConfigManager(); }

  void TearDown() override {
    auto &manager = ConfigManager::getInstance();
    auto &context = manager.getCurrentContext();

    delete context.locationContext->conf;
    delete context.serverContext->conf;
    delete context.httpContext->conf;
    delete context.globalContext->conf;

    delete context.locationContext;
    delete context.serverContext;
    delete context.httpContext;
    delete context.globalContext;

    std::filesystem::remove_all("test_logs");
  }

  static GlobalTestEnvironment *getInstance() { return new GlobalTestEnvironment(); }

private:
  GlobalTestEnvironment() = default;
  static void initialConfigManager();
};

} // namespace server::testing
