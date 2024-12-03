#pragma once

#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>

namespace server {

enum class LogLevel { TRACE, DEBUG, INFO, WARN, ERROR, FATAL };

class LogEntry {
public:
  LogEntry(LogLevel level, std::string_view message);

  LogLevel getLevel() const;
  std::string_view getMessage() const;
  const auto &getTimestamp() const;
  std::string_view getFile() const;
  int getLine() const;

private:
  LogLevel level_;
  std::string message_;
  std::chrono::system_clock::time_point timestamp_;
  std::string file_;
  int line_;
};

class LogFormatter {
public:
  std::string format(const LogEntry &entry) const;

private:
  static const char *getLevelName(LogLevel level);
  static const char *getLevelColor(LogLevel level);
};

class LogWriter {
public:
  void writeConsole(const std::string &message);
  void writeFile(const std::string &message, const std::filesystem::path &path);

private:
  std::mutex fileMutex_;
};

class Logger {
public:
  static void log(LogLevel level, std::string_view message);
  static void
  log(LogLevel level, std::string_view message, const std::filesystem::path &outputPath);
  static void setDefaultOutputFile(const std::filesystem::path &path);
  static void clearDefaultOutputFile();

private:
  static std::filesystem::path defaultOutputPath_;
  static LogFormatter formatter_;
  static LogWriter writer_;
};

} // namespace server
