#include "include/log.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

class LoggerTest : public ::testing::Test {
protected:
  void SetUp() override {

    if (std::filesystem::exists(test_log_file_)) {
      std::filesystem::remove(test_log_file_);
    }

    server::Logger::clearDefaultOutputFile();
  }

  void TearDown() override {

    if (std::filesystem::exists(test_log_file_)) {
      std::filesystem::remove(test_log_file_);
    }
  }

  std::string readLogFile(const std::filesystem::path &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
      return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
  }

  const std::filesystem::path test_log_file_ = "test.log";
};

TEST_F(LoggerTest, BasicLogging) {
  testing::internal::CaptureStdout();

  server::Logger::log(server::LogLevel::INFO, "Test message");

  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_TRUE(output.find("Test message") != std::string::npos);
  EXPECT_TRUE(output.find("INFO") != std::string::npos);
}

TEST_F(LoggerTest, LogToFile) {
  server::Logger::log(server::LogLevel::ERROR, "Error message", test_log_file_);

  std::string log_content = readLogFile(test_log_file_);
  EXPECT_TRUE(log_content.find("Error message") != std::string::npos);
  EXPECT_TRUE(log_content.find("ERROR") != std::string::npos);
}

TEST_F(LoggerTest, DefaultOutputFile) {
  server::Logger::setDefaultOutputFile(test_log_file_);
  server::Logger::log(server::LogLevel::DEBUG, "Debug message");

  std::string log_content = readLogFile(test_log_file_);
  EXPECT_TRUE(log_content.find("Debug message") != std::string::npos);
  EXPECT_TRUE(log_content.find("DEBUG") != std::string::npos);
}

TEST_F(LoggerTest, ClearDefaultOutputFile) {
  server::Logger::setDefaultOutputFile(test_log_file_);
  server::Logger::clearDefaultOutputFile();
  server::Logger::log(server::LogLevel::INFO, "Test message");

  EXPECT_FALSE(std::filesystem::exists(test_log_file_));
}

TEST_F(LoggerTest, MultipleLogLevels) {
  testing::internal::CaptureStdout();

  server::Logger::log(server::LogLevel::TRACE, "Trace message");
  server::Logger::log(server::LogLevel::DEBUG, "Debug message");
  server::Logger::log(server::LogLevel::INFO, "Info message");
  server::Logger::log(server::LogLevel::WARN, "Warning message");
  server::Logger::log(server::LogLevel::ERROR, "Error message");
  server::Logger::log(server::LogLevel::FATAL, "Fatal message");

  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_TRUE(output.find("TRACE") != std::string::npos);
  EXPECT_TRUE(output.find("DEBUG") != std::string::npos);
  EXPECT_TRUE(output.find("INFO") != std::string::npos);
  EXPECT_TRUE(output.find("WARN") != std::string::npos);
  EXPECT_TRUE(output.find("ERROR") != std::string::npos);
  EXPECT_TRUE(output.find("FATAL") != std::string::npos);
}

TEST_F(LoggerTest, LogFormatting) {
  testing::internal::CaptureStdout();

  server::Logger::log(server::LogLevel::INFO, "Test message");

  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_TRUE(output.find("[") != std::string::npos);
  EXPECT_TRUE(output.find("]") != std::string::npos);

  EXPECT_TRUE(output.find(".cpp") != std::string::npos);
  EXPECT_TRUE(output.find(":") != std::string::npos);
}

TEST_F(LoggerTest, ConcurrentFileAccess) {
  const int num_threads = 10;
  std::vector<std::thread> threads;

  server::Logger::setDefaultOutputFile(test_log_file_);

  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([i]() {
      server::Logger::log(server::LogLevel::INFO, "Message from thread " + std::to_string(i));
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  std::string log_content = readLogFile(test_log_file_);
  for (int i = 0; i < num_threads; ++i) {
    EXPECT_TRUE(log_content.find("Message from thread " + std::to_string(i)) != std::string::npos);
  }
}

TEST_F(LoggerTest, LogToInvalidFile) {
  testing::internal::CaptureStderr();

  server::Logger::log(server::LogLevel::INFO, "Test message", "/invalid/path/test.log");

  std::string error_output = testing::internal::GetCapturedStderr();
  EXPECT_TRUE(error_output.find("Failed to open log file") != std::string::npos);
}

TEST_F(LoggerTest, EmptyMessage) {
  testing::internal::CaptureStdout();

  server::Logger::log(server::LogLevel::INFO, "");

  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_TRUE(output.find("INFO") != std::string::npos);
}
