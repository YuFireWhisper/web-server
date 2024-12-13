#include "include/config_manager.h"

#include <gtest/gtest.h>

namespace server {

namespace {
constexpr int kDefaultConfigValue = 42;
} // namespace

class ConfigManagerTest : public ::testing::Test {
protected:
  ConfigManager manager_;
  ConfigPtr conf_{std::make_shared<int>(kDefaultConfigValue)};
};

TEST_F(ConfigManagerTest, RegisterSingleCommandSuccessfully) {
  const ServerCommand cmd{
      .name = "test_cmd",
      .type = CommandType::configNoArgs,
      .set  = nullptr,
      .post = nullptr
  };

  manager_.registerCommand(cmd);
  EXPECT_TRUE(manager_.handleCommand("test_cmd", "", conf_));
}

TEST_F(ConfigManagerTest, RegisterMultipleCommandsSuccessfully) {
  const std::vector<ServerCommand> cmds = {
      {.name = "cmd1", .type = CommandType::configNoArgs, .set = nullptr, .post = nullptr},
      {.name = "cmd2", .type = CommandType::configTake1, .set = nullptr, .post = nullptr}
  };

  manager_.registerCommands(cmds);
  EXPECT_TRUE(manager_.handleCommand("cmd1", "", conf_));
  EXPECT_TRUE(manager_.handleCommand("cmd2", "", conf_));
}

TEST_F(ConfigManagerTest, HandleUnregisteredCommandReturnsFalse) {
  EXPECT_FALSE(manager_.handleCommand("nonexistent", "", conf_));
}

TEST_F(ConfigManagerTest, HandleCommandWithSetFunctionSuccess) {
  bool setFunctionCalled = false;
  const ServerCommand cmd{
      .name = "set_cmd",
      .type = CommandType::configTake1,
      .set  = [&](const ConfigPtr &, const std::string &) -> char  *{
        setFunctionCalled = true;
        return nullptr;
      },
      .post = nullptr
  };

  manager_.registerCommand(cmd);
  EXPECT_TRUE(manager_.handleCommand("set_cmd", "value", conf_));
  EXPECT_TRUE(setFunctionCalled);
}

TEST_F(ConfigManagerTest, HandleCommandWithSetFunctionFailure) {
  const ServerCommand cmd{
      .name = "fail_cmd",
      .type = CommandType::configTake1,
      .set  = [](const ConfigPtr &, const std::string &) -> char  *{
        return const_cast<char *>("error");
      },
      .post = nullptr
  };

  manager_.registerCommand(cmd);
  EXPECT_FALSE(manager_.handleCommand("fail_cmd", "value", conf_));
}

TEST_F(ConfigManagerTest, HandleCommandWithPostFunctionSuccess) {
  bool postFunctionCalled = false;
  const ServerCommand cmd{
      .name = "post_cmd",
      .type = CommandType::configNoArgs,
      .set  = nullptr,
      .post = [&](const ConfigPtr &) -> void * {
        postFunctionCalled = true;
        return nullptr;
      }
  };

  manager_.registerCommand(cmd);
  EXPECT_TRUE(manager_.handleCommand("post_cmd", "", conf_));
  EXPECT_TRUE(postFunctionCalled);
}

TEST_F(ConfigManagerTest, HandleCommandWithPostFunctionFailure) {
  const ServerCommand cmd{
      .name = "post_fail",
      .type = CommandType::configNoArgs,
      .set  = nullptr,
      .post = [](const ConfigPtr &) -> void * {
        return const_cast<void *>(static_cast<const void *>("error"));
      }
  };

  manager_.registerCommand(cmd);
  EXPECT_FALSE(manager_.handleCommand("post_fail", "", conf_));
}

TEST_F(ConfigManagerTest, HandleCommandWithBothSetAndPostFunctions) {
  bool setFunctionCalled  = false;
  bool postFunctionCalled = false;

  const ServerCommand cmd{
      .name = "both_cmd",
      .type = CommandType::configTake1,
      .set  = [&](const ConfigPtr &, const std::string &) -> char  *{
        setFunctionCalled = true;
        return nullptr;
      },
      .post = [&](const ConfigPtr &) -> void * {
        postFunctionCalled = true;
        return nullptr;
      }
  };

  manager_.registerCommand(cmd);
  EXPECT_TRUE(manager_.handleCommand("both_cmd", "value", conf_));
  EXPECT_TRUE(setFunctionCalled);
  EXPECT_TRUE(postFunctionCalled);
}

} // namespace server
