#include "include/log.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>
#include <thread>

namespace server::testing {
using std::distance;
using std::istreambuf_iterator;

class LoggerTest : public ::testing::Test {
protected:
  void SetUp() override {
    tempDir_ = std::filesystem::temp_directory_path() / "logger_test";
    if (std::filesystem::exists(tempDir_)) {
      std::filesystem::remove_all(tempDir_);
    }
    std::filesystem::create_directories(tempDir_);

    systemLogPath_ = tempDir_ / "system.log";
    customLogPath_ = tempDir_ / "custom.log";

    log_detail::Logger::setSystemLogPath(systemLogPath_.string());
    log_detail::Logger::clearDefaultOutputFile();
  }

  void TearDown() override { std::filesystem::remove_all(tempDir_); }

  static std::string readLogFile(const std::filesystem::path &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
      std::cerr << "Failed to open file: " << path << " (errno: " << errno << ")" << '\n';
      return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
  }

  static bool logContainsEntry(
      const std::string &content,
      const std::string &level,
      const std::string &message,
      const std::string &function = ".*"
  ) {
    const std::string dateTimePattern  = R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})";
    const std::string levelPattern     = R"(\[)" + level + R"(\])";
    const std::string locationPattern  = R"([\w\/\-\.]+:\d+)";
    const std::string &functionPattern = function;
    const std::string &messagePattern  = message;

    std::string patternStr = "(" + dateTimePattern + ")" +         // Group 1: DateTime
                             " " + "(" + levelPattern + ")" +      // Group 2: Level
                             " " + "(" + locationPattern + ")" +   // Group 3: Location
                             " - " + "(" + functionPattern + ")" + // Group 4: Function
                             " - " + "(" + messagePattern + ")";   // Group 5: Message

    std::regex pattern(patternStr);
    std::smatch matches;

    std::cout << "\n=== Log Matcher Debug Info ===\n";
    std::cout << "Pattern Components:\n";
    std::cout << "- DateTime: " << dateTimePattern << '\n';
    std::cout << "- Level: " << levelPattern << '\n';
    std::cout << "- Location: " << locationPattern << '\n';
    std::cout << "- Function: " << functionPattern << '\n';
    std::cout << "- Message: " << messagePattern << '\n';
    std::cout << "\nFull Pattern: " << patternStr << '\n';
    std::cout << "Content to match: " << content << '\n';

    bool found = std::regex_search(content, matches, pattern);

    std::cout << "\nMatch Results:\n";
    std::cout << "Found match: " << (found ? "YES" : "NO") << '\n';

    if (found) {
      std::cout << "\nMatched Components:\n";
      std::cout << "- DateTime: " << matches[1] << '\n';
      std::cout << "- Level: " << matches[2] << '\n';
      std::cout << "- Location: " << matches[3] << '\n';
      std::cout << "- Function: " << matches[4] << '\n';
      std::cout << "- Message: " << matches[5] << '\n';
    }

    std::cout << "===========================\n";
    return found;
  }

  std::filesystem::path tempDir_;
  std::filesystem::path systemLogPath_;
  std::filesystem::path customLogPath_;
};

TEST_F(LoggerTest, BasicLogging) {
  Logger::log(LogLevel::INFO, "test message", "test.cpp", 1, "testFunction");

  std::string content = readLogFile(systemLogPath_);
  EXPECT_TRUE(logContainsEntry(content, "INFO", "test message", "testFunction"));
}

TEST_F(LoggerTest, MultipleLogLevels) {
  Logger::log(LogLevel::DEBUG, "debug message", "test.cpp", 1, "testFunction1");
  Logger::log(LogLevel::ERROR, "error message", "test.cpp", 2, "testFunction2");

  std::string content = readLogFile(systemLogPath_);
  EXPECT_TRUE(logContainsEntry(content, "DEBUG", "debug message", "testFunction1"));
  EXPECT_TRUE(logContainsEntry(content, "ERROR", "error message", "testFunction2"));
}

TEST_F(LoggerTest, CustomLogPath) {
  Logger::log(LogLevel::INFO, "custom path message", customLogPath_, "test.cpp", 1, "testFunction");

  std::string systemContent = readLogFile(systemLogPath_);
  std::string customContent = readLogFile(customLogPath_);

  EXPECT_TRUE(logContainsEntry(systemContent, "INFO", "custom path message", "testFunction"));
  EXPECT_TRUE(logContainsEntry(customContent, "INFO", "custom path message", "testFunction"));
}

TEST_F(LoggerTest, DefaultOutputFile) {
  std::filesystem::path defaultPath = tempDir_ / "default.log";
  Logger::setDefaultOutputFile(defaultPath);
  Logger::log(LogLevel::INFO, "default output message", "test.cpp", 1, "testFunction");

  std::string systemContent  = readLogFile(systemLogPath_);
  std::string defaultContent = readLogFile(defaultPath);

  EXPECT_TRUE(logContainsEntry(systemContent, "INFO", "default output message", "testFunction"));
  EXPECT_TRUE(logContainsEntry(defaultContent, "INFO", "default output message", "testFunction"));
}

TEST_F(LoggerTest, ClearDefaultOutputFile) {
  std::filesystem::path defaultPath = tempDir_ / "default.log";
  Logger::setDefaultOutputFile(defaultPath);
  Logger::clearDefaultOutputFile();
  Logger::log(LogLevel::INFO, "after clear message", "test.cpp", 1, "testFunction");

  EXPECT_TRUE(
      logContainsEntry(readLogFile(systemLogPath_), "INFO", "after clear message", "testFunction")
  );
  EXPECT_FALSE(std::filesystem::exists(defaultPath));
}

TEST_F(LoggerTest, ConcurrentLogging) {
  constexpr int threadCount   = 10;
  constexpr int logsPerThread = 100;

  std::vector<std::thread> threads;
  threads.reserve(threadCount);
  for (int i = 0; i < threadCount; ++i) {
    threads.emplace_back([i]() {
      std::string functionName = "ThreadFunction" + std::to_string(i);
      for (int j = 0; j < logsPerThread; ++j) {
        Logger::log(
            LogLevel::INFO,
            "thread " + std::to_string(i) + " message " + std::to_string(j),
            "test.cpp",
            i,
            functionName
        );
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  std::string content = readLogFile(systemLogPath_);
  int messageCount    = 0;

  std::regex pattern(R"(\[INFO\])");
  std::sregex_iterator it(content.begin(), content.end(), pattern);
  std::sregex_iterator end;
  messageCount = static_cast<int>(distance(it, end));

  EXPECT_EQ(messageCount, threadCount * logsPerThread);
}

TEST_F(LoggerTest, LogFileCreation) {
  std::filesystem::path deepPath = tempDir_ / "deep" / "nested" / "dir" / "test.log";
  Logger::log(LogLevel::INFO, "nested path message", deepPath, "test.cpp", 1, "testFunction");

  EXPECT_TRUE(std::filesystem::exists(deepPath));
  EXPECT_TRUE(logContainsEntry(readLogFile(deepPath), "INFO", "nested path message", "testFunction")
  );
}

TEST_F(LoggerTest, MacroUsage) {
  LOG_INFO("macro message");
  LOG_ERROR("error macro message");

  std::string content = readLogFile(systemLogPath_);
  EXPECT_TRUE(logContainsEntry(content, "INFO", "macro message", "TestBody"));
  EXPECT_TRUE(logContainsEntry(content, "ERROR", "error macro message", "TestBody"));
}

TEST_F(LoggerTest, FilePathMacroUsage) {
  LOG_INFO_F("custom file message", customLogPath_);

  EXPECT_TRUE(
      logContainsEntry(readLogFile(systemLogPath_), "INFO", "custom file message", "TestBody")
  );
  EXPECT_TRUE(
      logContainsEntry(readLogFile(customLogPath_), "INFO", "custom file message", "TestBody")
  );
}

} // namespace server::testing
