#include "include/log.h"

#include <chrono>
#include <ctime>
#include <exception>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <string_view>

namespace server {

std::filesystem::path Logger::default_output_file_;

namespace {
const std::map<LogLevel, std::string> LOG_COLORS = {{LogLevel::TRACE, "\033[36m"},
                                                    {LogLevel::DEBUG, "\033[34m"},
                                                    {LogLevel::INFO, "\033[32m"},
                                                    {LogLevel::WARN, "\033[33m"},
                                                    {LogLevel::ERROR, "\033[31m"},
                                                    {LogLevel::FATAL, "\033[1;31m"}};

const std::map<LogLevel, std::string> LOG_LEVEL_STRINGS = {{LogLevel::TRACE, "TRACE"},
                                                           {LogLevel::DEBUG, "DEBUG"},
                                                           {LogLevel::INFO, "INFO"},
                                                           {LogLevel::WARN, "WARN"},
                                                           {LogLevel::ERROR, "ERROR"},
                                                           {LogLevel::FATAL, "FATAL"}};
} // namespace

Logger::LogEntry::LogEntry(LogLevel level, std::string_view msg)
    : level(level), message(msg), timestamp(std::chrono::system_clock::now()) {
  file = __FILE__;
  line = __LINE__;
}

void Logger::log(LogLevel level, std::string_view message) {
  LogEntry entry(level, message);
  writeToConsole(entry);

  if (!default_output_file_.empty()) {
    writeToFile(entry, default_output_file_);
  }
}

void Logger::log(LogLevel level,
                 std::string_view message,
                 const std::filesystem::path &outputFile) {
  LogEntry entry(level, message);
  writeToConsole(entry);
  writeToFile(entry, outputFile);
}

void Logger::setDefaultOutputFile(const std::filesystem::path &path) {
  default_output_file_ = path;
}

void Logger::writeToConsole(const LogEntry &entry) {
  std::cout << formatLogMessage(entry) << std::endl;
}

void Logger::writeToFile(const LogEntry &entry, const std::filesystem::path &path) {
  try {
    std::ofstream outfile(path, std::ios::app);
    if (outfile) {
      outfile << formatLogMessage(entry) << std::endl;
    } else {
      std::cerr << "Failed to open log file: " << path << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error writing to log file: " << e.what() << std::endl;
  }
}

std::string Logger::formatLogMessage(const LogEntry &entry) {
  auto time = std::chrono::system_clock::to_time_t(entry.timestamp);
  auto tm = std::localtime(&time);
  char timestamp[32];
  std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

  return std::format("{}{} [{}] {}:{} - {}\033[0m",
                     getLevelColor(entry.level),
                     timestamp,
                     getLevelString(entry.level),
                     entry.file,
                     entry.line,
                     entry.message);
}

const std::string &Logger::getLevelString(LogLevel level) {
  return LOG_LEVEL_STRINGS.at(level);
}

const std::string &Logger::getLevelColor(LogLevel level) {
  return LOG_COLORS.at(level);
}

} // namespace server
