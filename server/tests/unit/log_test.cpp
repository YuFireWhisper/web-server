#include "include/log.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>
#include <sstream>
#include <thread>

namespace server::test {

class LogTestBase : public ::testing::Test {
protected:
  void SetUp() override {
    removeTestFiles();
    Logger::clearDefaultOutputFile();

    LogConfig config;
    config.systemLogPath = systemLogPath_;
    Logger::initialize(config);
  }

  void TearDown() override { removeTestFiles(); }

  [[nodiscard]] const std::filesystem::path &getSystemLogPath() const { return systemLogPath_; }

  [[nodiscard]] const std::filesystem::path &getCustomLogPath() const { return customLogPath_; }

  static std::string getTestFileContent(const std::filesystem::path &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
      return {};
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
  }

  static std::string captureConsoleOutput(const std::function<void()> &logOperation) {
    testing::internal::CaptureStdout();
    logOperation();
    return testing::internal::GetCapturedStdout();
  }

  static std::string captureErrorOutput(const std::function<void()> &logOperation) {
    testing::internal::CaptureStderr();
    logOperation();
    return testing::internal::GetCapturedStderr();
  }

  static void assertLogContains(
      const std::string &content,
      const std::string &expectedText,
      const std::string &levelName
  ) {
    std::regex timestamp_pattern(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})");
    ASSERT_TRUE(std::regex_search(content, timestamp_pattern))
        << "Missing timestamp in log: " << content;

    ASSERT_TRUE(content.find(levelName) != std::string::npos)
        << "Missing log level in: " << content;

    ASSERT_TRUE(content.find(expectedText) != std::string::npos)
        << "Missing message in: " << content;

    ASSERT_TRUE(content.find(".cpp") != std::string::npos) << "Missing source file in: " << content;
  }

private:
  const std::filesystem::path systemLogPath_{"system.log"};
  const std::filesystem::path customLogPath_{"custom.log"};

  void removeTestFiles() {
    if (std::filesystem::exists(systemLogPath_)) {
      std::filesystem::remove(systemLogPath_);
    }
    if (std::filesystem::exists(customLogPath_)) {
      std::filesystem::remove(customLogPath_);
    }
  }
};

TEST_F(LogTestBase, LogFormatterProducesCorrectFormat) {
  const LogEntry entry(LogLevel::INFO, "TestMessage");
  const std::string formatted = LogFormatter::format(entry);

  EXPECT_TRUE(formatted.find("\033[32m") != std::string::npos);
  EXPECT_TRUE(formatted.find("[INFO]") != std::string::npos);
  EXPECT_TRUE(formatted.find("TestMessage") != std::string::npos);
  EXPECT_TRUE(formatted.find("\033[0m") != std::string::npos);
}

TEST_F(LogTestBase, SystemLogCapturesAllMessages) {
  Logger::log(LogLevel::INFO, "TestMessage");

  const auto content = getTestFileContent(getSystemLogPath());
  assertLogContains(content, "TestMessage", "INFO");
}

TEST_F(LogTestBase, CustomLogFileReceivesMessages) {
  Logger::log(LogLevel::ERROR, "ErrorMessage", getCustomLogPath());

  const auto content = getTestFileContent(getCustomLogPath());
  assertLogContains(content, "ErrorMessage", "ERROR");
}

TEST_F(LogTestBase, ConsoleOutputContainsFormattedMessage) {
  const auto output = captureConsoleOutput([] { Logger::log(LogLevel::WARN, "WarnMessage"); });

  assertLogContains(output, "WarnMessage", "WARN");
}

TEST_F(LogTestBase, HandlesAllLogLevels) {
  const std::vector<std::pair<LogLevel, const char *>> levels = {
      {LogLevel::TRACE, "TRACE"},
      {LogLevel::DEBUG, "DEBUG"},
      {LogLevel::INFO, "INFO"},
      {LogLevel::WARN, "WARN"},
      {LogLevel::ERROR, "ERROR"},
      {LogLevel::FATAL, "FATAL"}
  };

  for (const auto &[level, name] : levels) {
    const auto output = captureConsoleOutput([level] { Logger::log(level, "TestMessage"); });
    assertLogContains(output, "TestMessage", name);
  }
}

TEST_F(LogTestBase, DefaultLogFileHandling) {
  Logger::setDefaultOutputFile(getCustomLogPath());
  Logger::log(LogLevel::DEBUG, "DebugMessage");

  const auto content = getTestFileContent(getCustomLogPath());
  assertLogContains(content, "DebugMessage", "DEBUG");
}

TEST_F(LogTestBase, ClearedDefaultFileStopsLogging) {
  Logger::setDefaultOutputFile(getCustomLogPath());
  Logger::clearDefaultOutputFile();
  Logger::log(LogLevel::INFO, "TestMessage");

  EXPECT_FALSE(std::filesystem::exists(getCustomLogPath()));
}

TEST_F(LogTestBase, ThreadSafety) {
  const int threadCount = 10;
  std::vector<std::thread> threads;
  Logger::setDefaultOutputFile(getCustomLogPath());

  threads.reserve(threadCount);
  for (int i = 0; i < threadCount; ++i) {
    threads.emplace_back([i] { Logger::log(LogLevel::INFO, "Thread" + std::to_string(i)); });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  const auto content = getTestFileContent(getCustomLogPath());
  for (int i = 0; i < threadCount; ++i) {
    ASSERT_TRUE(content.find("Thread" + std::to_string(i)) != std::string::npos);
  }
}

TEST_F(LogTestBase, HandlesInvalidFilePath) {
  const auto error =
      captureErrorOutput([] { Logger::log(LogLevel::INFO, "Test", "/invalid/path/test.log"); });

  EXPECT_TRUE(error.find("Failed to open log file") != std::string::npos);
}

TEST_F(LogTestBase, ConvenienceFunctionsWork) {
  const auto output = captureConsoleOutput([] {
    logTrace("Trace");
    logDebug("Debug");
    logInfo("Info");
    logWarn("Warn");
    logError("Error");
    logFatal("Fatal");
  });

  assertLogContains(output, "Trace", "TRACE");
  assertLogContains(output, "Debug", "DEBUG");
  assertLogContains(output, "Info", "INFO");
  assertLogContains(output, "Warn", "WARN");
  assertLogContains(output, "Error", "ERROR");
  assertLogContains(output, "Fatal", "FATAL");
}

} // namespace server::test
