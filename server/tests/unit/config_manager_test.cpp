#include "include/config_manager.h"
#include "include/types.h"

#include <gtest/gtest.h>

namespace server {

class ConfigManagerTest : public ::testing::Test {
protected:
  void SetUp() override { manager_.setCurrentText(manager_.getCurrentContext()); }

  ConfigManager &manager_{ ConfigManager::getInstance() };
};

TEST_F(ConfigManagerTest, RegisterSingleCommand) {
  ServerCommand cmd{ .name   = "test_cmd",
                     .type   = CommandType::global | CommandType::configNoArgs,
                     .offset = 0 };

  EXPECT_NO_THROW(manager_.registerCommand(cmd));
  EXPECT_NO_THROW(manager_.handleCommand({ "test_cmd" }));
}

TEST_F(ConfigManagerTest, RegisterMultipleCommands) {
  std::vector<ServerCommand> cmds = {
    { .name = "cmd1", .type = CommandType::global | CommandType::configNoArgs, .offset = 0 },
    { .name = "cmd2", .type = CommandType::global | CommandType::configNoArgs, .offset = 0 }
  };

  EXPECT_NO_THROW(manager_.registerCommands(cmds));
  EXPECT_NO_THROW(manager_.handleCommand({ "cmd1" }));
  EXPECT_NO_THROW(manager_.handleCommand({ "cmd2" }));
}

TEST_F(ConfigManagerTest, HandleUnregisteredCommand) {
  EXPECT_THROW(manager_.handleCommand({ "unknown_cmd" }), std::invalid_argument);
}

TEST_F(ConfigManagerTest, HandleEmptyConfig) {
  EXPECT_THROW(manager_.configParse(nullptr, 0), std::invalid_argument);
}

TEST_F(ConfigManagerTest, HandleContextManagement) {
  auto originalContext = manager_.getCurrentContext();
  originalContext.now  = kHttpOffset;

  EXPECT_NO_THROW(manager_.setCurrentText(originalContext));
  EXPECT_EQ(manager_.getCurrentContext().now, kHttpOffset);
}

TEST_F(ConfigManagerTest, GetContextByValidOffset) {
  EXPECT_NO_THROW(manager_.getContextByOffset(kGlobalOffset));
}

TEST_F(ConfigManagerTest, GetContextByInvalidOffset) {
  EXPECT_THROW(manager_.getContextByOffset(999), std::out_of_range);
}

TEST_F(ConfigManagerTest, ParseValidConfig) {
  ServerCommand cmd{ .name   = "test_cmd",
                     .type   = CommandType::global | CommandType::configNoArgs,
                     .offset = 0 };
  manager_.registerCommand(cmd);

  const char *config = "test_cmd ;   \n";
  const size_t len   = 15;
  EXPECT_NO_THROW(manager_.configParse(config, len));
}

TEST_F(ConfigManagerTest, HandleCommandWithValidArguments) {
  ServerCommand cmd{ .name   = "test_cmd",
                     .type   = CommandType::global | CommandType::configNoArgs,
                     .offset = 0 };

  manager_.registerCommand(cmd);
  EXPECT_NO_THROW(manager_.handleCommand({ "test_cmd" }));
}

TEST_F(ConfigManagerTest, HandleCommandWithInvalidArguments) {
  ServerCommand cmd{ .name   = "test_cmd",
                     .type   = CommandType::global | CommandType::configNoArgs,
                     .offset = 0 };

  manager_.registerCommand(cmd);
  EXPECT_THROW(manager_.handleCommand({ "test_cmd", "unexpected_arg" }), std::invalid_argument);
}

} // namespace server
