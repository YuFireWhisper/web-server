#include "include/log.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <thread>

namespace server::test {

class LogTestBase : public ::testing::Test {
protected:
  void SetUp() override {
    removeTestFile();
    Logger::clearDefaultOutputFile();
  }

  void TearDown() override { removeTestFile(); }

  std::string getTestFileContent() { return readFileContent(testFilePath_); }

  [[nodiscard]] const std::filesystem::path &getTestFilePath() const { return testFilePath_; }

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

  static void assertContains(const std::string &content, const std::string &expectedText) {
    EXPECT_TRUE(content.find(expectedText) != std::string::npos)
        << "Expected to find: " << expectedText << " in: " << content;
  }

private:
  const std::filesystem::path testFilePath_{"test.log"};

  void removeTestFile() {
    if (std::filesystem::exists(testFilePath_)) {
      std::filesystem::remove(testFilePath_);
    }
  }

  static std::string readFileContent(const std::filesystem::path &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
      return {};
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
  }
};

TEST_F(LogTestBase, ConsoleLogDisplaysMessageAndLevel) {
  auto output = captureConsoleOutput([] { Logger::log(LogLevel::INFO, "TestMessage"); });

  assertContains(output, "TestMessage");
  assertContains(output, "INFO");
}

TEST_F(LogTestBase, FileLogWritesMessageAndLevel) {
  Logger::log(LogLevel::ERROR, "ErrorMessage", getTestFilePath());
  auto fileContent = getTestFileContent();

  assertContains(fileContent, "ErrorMessage");
  assertContains(fileContent, "ERROR");
}

TEST_F(LogTestBase, DefaultFileWritesLogContent) {
  Logger::setDefaultOutputFile(getTestFilePath());
  Logger::log(LogLevel::DEBUG, "DebugMessage");
  auto fileContent = getTestFileContent();

  assertContains(fileContent, "DebugMessage");
  assertContains(fileContent, "DEBUG");
}

TEST_F(LogTestBase, ClearedDefaultFileCreatesNoFile) {
  Logger::setDefaultOutputFile(getTestFilePath());
  Logger::clearDefaultOutputFile();
  Logger::log(LogLevel::INFO, "TestMessage");

  EXPECT_FALSE(std::filesystem::exists(getTestFilePath()));
}

TEST_F(LogTestBase, LogFormatContainsRequiredElements) {
  auto output = captureConsoleOutput([] { Logger::log(LogLevel::INFO, "FormatTest"); });

  assertContains(output, "[");
  assertContains(output, "]");
  assertContains(output, ".cpp");
  assertContains(output, ":");
}

TEST_F(LogTestBase, SupportsAllLogLevels) {
  auto output = captureConsoleOutput([] {
    Logger::log(LogLevel::TRACE, "TraceMessage");
    Logger::log(LogLevel::DEBUG, "DebugMessage");
    Logger::log(LogLevel::INFO, "InfoMessage");
    Logger::log(LogLevel::WARN, "WarnMessage");
    Logger::log(LogLevel::ERROR, "ErrorMessage");
    Logger::log(LogLevel::FATAL, "FatalMessage");
  });

  assertContains(output, "TRACE");
  assertContains(output, "DEBUG");
  assertContains(output, "INFO");
  assertContains(output, "WARN");
  assertContains(output, "ERROR");
  assertContains(output, "FATAL");
}

TEST_F(LogTestBase, HandlesMultipleThreadsSafely) {
  const int threadCount = 10;
  std::vector<std::thread> threads;
  Logger::setDefaultOutputFile(getTestFilePath());

  threads.reserve(threadCount);
  for (int i = 0; i < threadCount; ++i) {
    threads.emplace_back([i] { Logger::log(LogLevel::INFO, "Thread" + std::to_string(i)); });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  auto fileContent = getTestFileContent();
  for (int i = 0; i < threadCount; ++i) {
    assertContains(fileContent, "Thread" + std::to_string(i));
  }
}

TEST_F(LogTestBase, HandlesInvalidFilePath) {
  auto error =
      captureErrorOutput([] { Logger::log(LogLevel::INFO, "Test", "/invalid/path/test.log"); });

  assertContains(error, "Failed to open log file");
}

TEST_F(LogTestBase, HandlesEmptyMessage) {
  auto output = captureConsoleOutput([] { Logger::log(LogLevel::INFO, ""); });

  assertContains(output, "INFO");
}

} // namespace server::test
