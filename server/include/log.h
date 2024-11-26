#pragma once
#include <string_view>
#include <filesystem>
#include <string>
#include <chrono>

namespace server {

enum class LogLevel {
  TRACE,
  DEBUG,
  INFO,
  WARN,
  ERROR,
  FATAL,
};

class Logger {
public:
  static void log(LogLevel level, std::string_view message);
  static void log(LogLevel level, std::string_view message, const std::filesystem::path& outputFile);
  static void setDefaultOutputFile(const std::filesystem::path& path);
  static void clearDefaultOutputFile() { default_output_file_.clear(); }

private:
  static std::filesystem::path default_output_file_;

  struct LogEntry {
    LogLevel level;
    std::string message;
    std::string file;
    int line;
    std::chrono::system_clock::time_point timestamp;

    LogEntry(LogLevel, std::string_view msg);
  };

  static void writeToConsole(const LogEntry& entry);
  static void writeToFile(const LogEntry& entry, const std::filesystem::path& file);
  static std::string formatLogMessage(const LogEntry& entry);

  static const std::string& getLevelString(LogLevel level);
  static const std::string& getLevelColor(LogLevel level);
};

};  // namespace server
