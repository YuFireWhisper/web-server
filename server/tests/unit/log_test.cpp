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
    removeTestDirectory();
    Logger::clearDefaultOutputFile();
  }

  void TearDown() override { removeTestDirectory(); }

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
  const std::filesystem::path testDir_{ "test_logs" };
  const std::filesystem::path testFilePath_{ testDir_ / "test.log" };

  void removeTestDirectory() {
    if (std::filesystem::exists(testDir_)) {
      std::filesystem::remove_all(testDir_);
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
  auto output = captureConsoleOutput([] { LOG_INFO("TestMessage"); });

  assertContains(output, "TestMessage");
  assertContains(output, "INFO");
}

TEST_F(LogTestBase, FileLogWritesMessageAndLevel) {
  LOG_ERROR_F("ErrorMessage", getTestFilePath());
  auto fileContent = getTestFileContent();

  assertContains(fileContent, "ErrorMessage");
  assertContains(fileContent, "ERROR");
}

TEST_F(LogTestBase, CreatesDirectoryStructure) {
  const auto nestedPath = std::filesystem::path{ "test_logs/nested/deep/test.log" };
  LOG_INFO_F("TestMessage", nestedPath);

  EXPECT_TRUE(std::filesystem::exists(nestedPath));
  EXPECT_TRUE(std::filesystem::exists(nestedPath.parent_path()));
}

TEST_F(LogTestBase, HandlesHomeDirectoryTilde) {
  const char *home = std::getenv("HOME");
  ASSERT_NE(home, nullptr);

  const auto tildeLogPath = std::filesystem::path{ "~/test_logs/tilde_test.log" };
  LOG_INFO_F("TestMessage", tildeLogPath);

  auto expectedPath = std::filesystem::path(home) / "test_logs/tilde_test.log";
  EXPECT_TRUE(std::filesystem::exists(expectedPath));
}

TEST_F(LogTestBase, DefaultFileWritesLogContent) {
  Logger::setDefaultOutputFile(getTestFilePath());
  LOG_DEBUG("DebugMessage");
  auto fileContent = getTestFileContent();

  assertContains(fileContent, "DebugMessage");
  assertContains(fileContent, "DEBUG");
}

TEST_F(LogTestBase, ClearedDefaultFileCreatesNoFile) {
  Logger::setDefaultOutputFile(getTestFilePath());
  Logger::clearDefaultOutputFile();
  LOG_INFO("TestMessage");

  EXPECT_FALSE(std::filesystem::exists(getTestFilePath()));
}

TEST_F(LogTestBase, LogFormatContainsRequiredElements) {
  auto output = captureConsoleOutput([] { LOG_INFO("FormatTest"); });

  assertContains(output, "[");
  assertContains(output, "]");
  assertContains(output, ".cpp");
  assertContains(output, ":");
}

TEST_F(LogTestBase, SupportsAllLogLevels) {
  auto output = captureConsoleOutput([] {
    LOG_TRACE("TraceMessage");
    LOG_DEBUG("DebugMessage");
    LOG_INFO("InfoMessage");
    LOG_WARN("WarnMessage");
    LOG_ERROR("ErrorMessage");
    LOG_FATAL("FatalMessage");
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
    threads.emplace_back([i] { LOG_INFO("Thread" + std::to_string(i)); });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  auto fileContent = getTestFileContent();
  for (int i = 0; i < threadCount; ++i) {
    assertContains(fileContent, "Thread" + std::to_string(i));
  }
}

TEST_F(LogTestBase, HandlesNonExistentParentDirectory) {
  const auto deepPath = std::filesystem::path{ "/tmp/non_existent_dir/deeper/test.log" };
  LOG_INFO_F("Test", deepPath);
  EXPECT_TRUE(std::filesystem::exists(deepPath));
}

TEST_F(LogTestBase, HandlesEmptyMessage) {
  auto output = captureConsoleOutput([] { LOG_INFO(""); });
  assertContains(output, "INFO");
}

TEST_F(LogTestBase, HandlesSymlinks) {
  const auto actualDir = std::filesystem::path{ "test_logs/actual" };
  const auto linkDir   = std::filesystem::path{ "test_logs/link" };

  if (std::filesystem::exists("test_logs")) {
    std::filesystem::remove_all("test_logs");
  }

  std::filesystem::create_directories(actualDir);

  std::filesystem::create_symlink("actual", linkDir);

  ASSERT_TRUE(std::filesystem::exists(linkDir));
  ASSERT_TRUE(std::filesystem::is_symlink(linkDir));

  const auto logPath = linkDir / "test.log";
  LOG_INFO_F("TestMessage", logPath);

  EXPECT_TRUE(std::filesystem::exists(linkDir / "test.log"));
  EXPECT_TRUE(std::filesystem::exists(actualDir / "test.log"));
}
} // namespace server::test
