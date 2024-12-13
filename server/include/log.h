#pragma once

#include "include/config_types.h"

#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>

namespace server {

enum class LogLevel : int8_t { TRACE, DEBUG, INFO, WARN, ERROR, FATAL };

class LogEntry {
public:
  LogEntry(LogLevel level, std::string_view message);

  [[nodiscard]] LogLevel getLevel() const;
  [[nodiscard]] std::string_view getMessage() const;
  [[nodiscard]] const auto &getTimestamp() const;
  [[nodiscard]] std::string_view getFile() const;
  [[nodiscard]] int getLine() const;

private:
  LogLevel level_;
  std::string message_;
  std::chrono::system_clock::time_point timestamp_;
  std::string file_;
  int line_;
};

class LogFormatter {
public:
  [[nodiscard]] static std::string format(const LogEntry &entry);

private:
  static const char *getLevelName(LogLevel level);
  static const char *getLevelColor(LogLevel level);
};

class LogWriter {
public:
  static void writeConsole(const std::string &message);
  void writeFile(const std::string &message, const std::filesystem::path &path);

private:
  std::mutex fileMutex_;
};

class Logger {
public:
  static void initialize(const LogConfig& config);
  static void log(LogLevel level, std::string_view message);
  static void
  log(LogLevel level, std::string_view message, const std::filesystem::path &outputPath);
  static void setDefaultOutputFile(const std::filesystem::path &path);
  static void clearDefaultOutputFile();

private:
  static std::filesystem::path systemLogPath_;
  static std::filesystem::path defaultOutputPath_;
  static LogWriter writer_;
};

inline void logTrace(std::string_view message) {
  Logger::log(LogLevel::TRACE, message);
}

inline void logDebug(std::string_view message) {
  Logger::log(LogLevel::DEBUG, message);
}

inline void logInfo(std::string_view message) {
  Logger::log(LogLevel::INFO, message);
}

inline void logWarn(std::string_view message) {
  Logger::log(LogLevel::WARN, message);
}

inline void logError(std::string_view message) {
  Logger::log(LogLevel::ERROR, message);
}

inline void logFatal(std::string_view message) {
  Logger::log(LogLevel::FATAL, message);
}

inline void logTrace(std::string_view message, const std::filesystem::path &path) {
  Logger::log(LogLevel::TRACE, message, path);
}

inline void logDebug(std::string_view message, const std::filesystem::path &path) {
  Logger::log(LogLevel::DEBUG, message, path);
}

inline void logInfo(std::string_view message, const std::filesystem::path &path) {
  Logger::log(LogLevel::INFO, message, path);
}

inline void logWarn(std::string_view message, const std::filesystem::path &path) {
  Logger::log(LogLevel::WARN, message, path);
}

inline void logError(std::string_view message, const std::filesystem::path &path) {
  Logger::log(LogLevel::ERROR, message, path);
}

inline void logFatal(std::string_view message, const std::filesystem::path &path) {
  Logger::log(LogLevel::FATAL, message, path);
}

} // namespace server
