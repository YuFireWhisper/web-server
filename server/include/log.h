#pragma once

#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>

#define LOG_TRACE(message) Logger::log(LogLevel::TRACE, message, __FILE__, __LINE__)
#define LOG_DEBUG(message) Logger::log(LogLevel::DEBUG, message, __FILE__, __LINE__)
#define LOG_INFO(message) Logger::log(LogLevel::INFO, message, __FILE__, __LINE__)
#define LOG_WARN(message) Logger::log(LogLevel::WARN, message, __FILE__, __LINE__)
#define LOG_ERROR(message) Logger::log(LogLevel::ERROR, message, __FILE__, __LINE__)
#define LOG_FATAL(message) Logger::log(LogLevel::FATAL, message, __FILE__, __LINE__)

#define LOG_TRACE_F(message, path) Logger::log(LogLevel::TRACE, message, path, __FILE__, __LINE__)
#define LOG_DEBUG_F(message, path) Logger::log(LogLevel::DEBUG, message, path, __FILE__, __LINE__)
#define LOG_INFO_F(message, path) Logger::log(LogLevel::INFO, message, path, __FILE__, __LINE__)
#define LOG_WARN_F(message, path) Logger::log(LogLevel::WARN, message, path, __FILE__, __LINE__)
#define LOG_ERROR_F(message, path) Logger::log(LogLevel::ERROR, message, path, __FILE__, __LINE__)
#define LOG_FATAL_F(message, path) Logger::log(LogLevel::FATAL, message, path, __FILE__, __LINE__)

namespace server {

enum class LogLevel : int8_t { TRACE, DEBUG, INFO, WARN, ERROR, FATAL };

class LogEntry {
public:
  LogEntry(LogLevel level, std::string_view message, std::string_view file, int line);

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
  static bool ensureFileExists(const std::filesystem::path &path);
  std::mutex fileMutex_;
};

class Logger {
public:
  static void log(LogLevel level, std::string_view message, std::string_view file, int line);
  static void
  log(LogLevel level,
      std::string_view message,
      const std::filesystem::path &outputPath,
      std::string_view file,
      int line);
  static void setDefaultOutputFile(const std::filesystem::path &path);
  static void clearDefaultOutputFile();

private:
  static std::string systemLogPath_;
  static std::filesystem::path defaultOutputPath_;
  static LogWriter writer_;
};

} // namespace server
