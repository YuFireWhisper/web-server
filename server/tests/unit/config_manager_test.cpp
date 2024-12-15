#include "include/config_manager.h"

#include <gtest/gtest.h>

namespace server {

namespace {
constexpr int kDefaultConfigValue = 42;
}

class ConfigManagerTest : public ::testing::Test {
protected:
  ConfigManager manager_;
  ConfigPtr conf_{std::make_shared<int>(kDefaultConfigValue)};
};

TEST_F(ConfigManagerTest, HandlesSingleRegisteredCommandSuccessfully) {
  const ServerCommand cmd{
      .name   = "test_cmd",
      .type   = CommandType::configNoArgs,
      .offset = 0,
      .set    = nullptr,
      .post   = nullptr
  };

  manager_.registerCommand(cmd);
  EXPECT_TRUE(manager_.handleCommand("test_cmd", "", conf_));
}

TEST_F(ConfigManagerTest, HandlesMultipleRegisteredCommandsSuccessfully) {
  const std::vector<ServerCommand> cmds = {
      {.name   = "cmd1",
       .type   = CommandType::configNoArgs,
       .offset = 0,
       .set    = nullptr,
       .post   = nullptr},
      {.name   = "cmd2",
       .type   = CommandType::configTake1,
       .offset = 0,
       .set    = nullptr,
       .post   = nullptr}
  };

  manager_.registerCommands(cmds);
  EXPECT_TRUE(manager_.handleCommand("cmd1", "", conf_));
  EXPECT_TRUE(manager_.handleCommand("cmd2", "value", conf_));
}

TEST_F(ConfigManagerTest, ReturnsFalseForUnregisteredCommand) {
  EXPECT_FALSE(manager_.handleCommand("nonexistent", "", conf_));
}

TEST_F(ConfigManagerTest, ReturnsFalseForArgumentCountMismatch) {
  const std::vector<ServerCommand> cmds = {
      {.name   = "no_args",
       .type   = CommandType::configNoArgs,
       .offset = 0,
       .set    = nullptr,
       .post   = nullptr},
      {.name   = "one_arg",
       .type   = CommandType::configTake1,
       .offset = 0,
       .set    = nullptr,
       .post   = nullptr}
  };

  manager_.registerCommands(cmds);
  EXPECT_FALSE(manager_.handleCommand("no_args", "value", conf_));
  EXPECT_FALSE(manager_.handleCommand("one_arg", "", conf_));
}

TEST_F(ConfigManagerTest, ExecutesSetFunctionSuccessfully) {
  bool setFunctionCalled = false;
  const ServerCommand cmd{
      .name   = "set_cmd",
      .type   = CommandType::configTake1,
      .offset = 0,
      .set    = [&](const ConfigPtr &, const std::string &, size_t) -> char    *{
        setFunctionCalled = true;
        return nullptr;
      },
      .post = nullptr
  };

  manager_.registerCommand(cmd);
  EXPECT_TRUE(manager_.handleCommand("set_cmd", "value", conf_));
  EXPECT_TRUE(setFunctionCalled);
}

TEST_F(ConfigManagerTest, ReturnsFalseWhenSetFunctionFails) {
  const ServerCommand cmd{
      .name   = "fail_cmd",
      .type   = CommandType::configTake1,
      .offset = 0,
      .set    = [](const ConfigPtr &, const std::string &, size_t) -> char    *{
        return strdup("error");
      },
      .post = nullptr
  };

  manager_.registerCommand(cmd);
  EXPECT_FALSE(manager_.handleCommand("fail_cmd", "value", conf_));
}

TEST_F(ConfigManagerTest, HandlesAllConfigTypesCorrectly) {
  struct TestConfig {
    bool flagValue = false;
    int numValue   = 0;
    std::string strValue;
  };
  auto config = std::make_shared<TestConfig>();

  const std::vector<ServerCommand> cmds = {
      {.name   = "flag_cmd",
       .type   = CommandType::configFlag | CommandType::configTake1,
       .offset = offsetof(TestConfig, flagValue),
       .set    = nullptr,
       .post   = nullptr},
      {.name   = "num_cmd",
       .type   = CommandType::configNumber | CommandType::configTake1,
       .offset = offsetof(TestConfig, numValue),
       .set    = nullptr,
       .post   = nullptr},
      {.name   = "str_cmd",
       .type   = CommandType::configString | CommandType::configTake1,
       .offset = offsetof(TestConfig, strValue),
       .set    = nullptr,
       .post   = nullptr}
  };

  manager_.registerCommands(cmds);

  EXPECT_TRUE(manager_.handleCommand("flag_cmd", "on", config));
  EXPECT_TRUE(config->flagValue);
  EXPECT_TRUE(manager_.handleCommand("flag_cmd", "true", config));
  EXPECT_TRUE(config->flagValue);
  EXPECT_TRUE(manager_.handleCommand("flag_cmd", "1", config));
  EXPECT_TRUE(config->flagValue);

  EXPECT_TRUE(manager_.handleCommand("num_cmd", "42", config));
  EXPECT_EQ(42, config->numValue);

  EXPECT_TRUE(manager_.handleCommand("str_cmd", "test", config));
  EXPECT_EQ("test", config->strValue);
}

TEST_F(ConfigManagerTest, ReturnsFalseForInvalidConfigValues) {
  struct TestConfig {
    int numValue = 0;
    std::string strValue;
  };
  auto config = std::make_shared<TestConfig>();

  const std::vector<ServerCommand> cmds = {
      {.name   = "num_cmd",
       .type   = CommandType::configNumber | CommandType::configTake1,
       .offset = offsetof(TestConfig, numValue),
       .set    = nullptr,
       .post   = nullptr},
      {.name   = "str_cmd",
       .type   = CommandType::configString | CommandType::configTake1,
       .offset = offsetof(TestConfig, strValue),
       .set    = nullptr,
       .post   = nullptr}
  };

  manager_.registerCommands(cmds);

  EXPECT_FALSE(manager_.handleCommand("num_cmd", "not_a_number", config));

  const ServerCommand invalidCmd{
      .name   = "invalid_type",
      .type   = static_cast<CommandType>(0xFF00),
      .offset = 0,
      .set    = nullptr,
      .post   = nullptr
  };
  manager_.registerCommand(invalidCmd);
  EXPECT_FALSE(manager_.handleCommand("invalid_type", "value", config));
}

} // namespace server
