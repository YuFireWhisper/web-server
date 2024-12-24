#include "include/config_commands.h"
#include "include/config_manager.h"

#include <gtest/gtest.h>

namespace server::testing {

class GlobalTestEnvironment : public ::testing::Environment {
public:
  void SetUp() override {
    auto& manager = ConfigManager::getInstance();
    manager.registerCommands(getAllCommands());
  }

  void TearDown() override {
    std::filesystem::remove_all("test_logs");
  }

  static GlobalTestEnvironment* getInstance() { 
    return new GlobalTestEnvironment(); 
  }

private:
  GlobalTestEnvironment() = default;
};

} // namespace server::testing
