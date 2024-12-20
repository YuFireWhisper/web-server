#include "include/log.h"

#include "auto/auto_config.h"

#include <array>
#include <format>
#include <fstream>
#include <iostream>

namespace server {

namespace {
constexpr std::array<const char *, 6> LEVEL_NAMES = { "TRACE", "DEBUG", "INFO",
                                                      "WARN",  "ERROR", "FATAL" };

constexpr std::array<const char *, 6> LEVEL_COLORS = { "\033[36m", "\033[34m", "\033[32m",
                                                       "\033[33m", "\033[31m", "\033[1;31m" };
} // namespace

LogEntry::LogEntry(LogLevel level, std::string_view message, std::string_view file, int line)
    : level_(level)
    , message_(message)
    , timestamp_(std::chrono::system_clock::now())
    , file_(file)
    , line_(line) {}

LogLevel LogEntry::getLevel() const {
  return level_;
}

std::string_view LogEntry::getMessage() const {
  return message_;
}

const auto &LogEntry::getTimestamp() const {
  return timestamp_;
}

std::string_view LogEntry::getFile() const {
  return file_;
}

int LogEntry::getLine() const {
  return line_;
}

const char *LogFormatter::getLevelName(LogLevel level) {
  return LEVEL_NAMES[static_cast<size_t>(level)];
}

const char *LogFormatter::getLevelColor(LogLevel level) {
  return LEVEL_COLORS[static_cast<size_t>(level)];
}

std::string LogFormatter::format(const LogEntry &entry) {
  auto time       = std::chrono::system_clock::to_time_t(entry.getTimestamp());
  auto *localTime = std::localtime(&time);

  const static size_t timeStampSize = 32;
  std::array<char, timeStampSize> timestamp;
  std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%d %H:%M:%S", localTime);

  std::string timestampStr(timestamp.data());

  return std::format(
      "{}{} [{}] {}:{} - {}\033[0m",
      getLevelColor(entry.getLevel()),
      timestampStr,
      getLevelName(entry.getLevel()),
      entry.getFile(),
      entry.getLine(),
      entry.getMessage()
  );
}

void LogWriter::writeConsole(const std::string &message) {
  std::cout << message << '\n';
}

void LogWriter::writeFile(const std::string &message, const std::filesystem::path &path) {
  std::lock_guard<std::mutex> lock(fileMutex_);

  std::ofstream outfile(path, std::ios::app);
  if (!outfile) {
    std::cerr << "Failed to open log file: " << path << '\n';
    return;
  }

  outfile << message << '\n';
}

std::filesystem::path Logger::defaultOutputPath_;
LogWriter Logger::writer_;

void Logger::log(LogLevel level, std::string_view message, std::string_view file, int line) {
  LogEntry entry(level, message, file, line);
  auto formattedMessage = LogFormatter::format(entry);

  LogWriter::writeConsole(formattedMessage);
  writer_.writeFile(formattedMessage, kSystemLog);

  if (!defaultOutputPath_.empty()) {
    writer_.writeFile(formattedMessage, defaultOutputPath_);
  }
}

void Logger::log(
    LogLevel level,
    std::string_view message,
    const std::filesystem::path &outputPath,
    std::string_view file,
    int line
) {
  LogEntry entry(level, message, file, line);
  auto formattedMessage = LogFormatter::format(entry);

  LogWriter::writeConsole(formattedMessage);
  writer_.writeFile(formattedMessage, kSystemLog);
  writer_.writeFile(formattedMessage, outputPath);
}

void Logger::setDefaultOutputFile(const std::filesystem::path &path) {
  defaultOutputPath_ = path;
}

void Logger::clearDefaultOutputFile() {
  defaultOutputPath_.clear();
}

} // namespace server
