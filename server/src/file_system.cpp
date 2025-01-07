#include "include/file_system.h"

#include <filesystem>
#include <fstream>
#include <string>

namespace server {
std::string FileSystem::toAbsolutePath(const std::string &path) {
  if (path[0] == '/' || path[0] == '~') {
    return path;
  }

  if (!path.empty() && path[0] == '~') {
    const char *homeDir = std::getenv("HOME");
    if (homeDir == nullptr) {
      throw std::runtime_error("無法獲取HOME目錄");
    }
    size_t skipLength = (path.length() > 1 && path[1] == '/') ? 2 : 1;
    return std::filesystem::path(homeDir) / path.substr(skipLength);
  }

  return std::filesystem::absolute(path);
}

void FileSystem::addLineToFile(const std::string &path, const std::string &line, size_t index) {
  std::fstream file;
  if (isNoneExist(path)) {
    file.open(path, std::ios::out);
    file.close();
  }

  file.open(path, std::ios::in | std::ios::out);
  if (!file) {
    file.open(path, std::ios::out);
    if (!file) {
      throw std::runtime_error("Failed to create/open file: " + path);
    }
    file.close();
    file.open(path, std::ios::in | std::ios::out);
  }

  long position = static_cast<long>(index * LINE_LENGTH);
  if (position < 0) {
    throw std::runtime_error("Invalid index: negative position");
  }

  file.seekp(position);
  if (file.fail()) {
    throw std::runtime_error("Failed to seek to position: " + std::to_string(position));
  }

  std::string paddedUrl = line;
  paddedUrl.resize(LINE_LENGTH - 1, ' ');

  file << paddedUrl << '\n';
  if (file.fail()) {
    throw std::runtime_error("Failed to write line at index: " + std::to_string(index));
  }

  file.close();
}

std::string FileSystem::readLineFromFile(const std::string &path, size_t index) {
  if (isNoneExist(path)) {
    return "";
  }

  std::fstream file(path, std::ios::in);
  if (!file) {
    throw std::runtime_error("Failed to open file: " + path);
  }

  long position = static_cast<long>(index * LINE_LENGTH);
  if (position < 0) {
    throw std::runtime_error("Invalid index: negative position");
  }

  file.seekg(position);
  if (file.fail()) {
    throw std::runtime_error("Failed to seek to position: " + std::to_string(position));
  }

  std::string line;
  if (!std::getline(file, line)) {
    return "";
  }

  if (!line.empty()) {
    auto last = line.find_last_not_of(" \n\r\t");
    if (last != std::string::npos) {
      line.erase(last + 1);
    }
  }

  file.close();
  return line;
}

void FileSystem::removeLineFromFile(const std::string &path, size_t index) {
  if (isNoneExist(path)) {
    throw std::runtime_error("File not exist: " + path);
  }

  std::fstream file(path, std::ios::in | std::ios::out);
  if (!file) {
    throw std::runtime_error("Failed to open file: " + path);
  }

  long position = static_cast<long>(index * LINE_LENGTH);
  if (position < 0) {
    throw std::runtime_error("Invalid index: negative position");
  }

  file.seekp(position);
  if (file.fail()) {
    throw std::runtime_error("Failed to seek to position: " + std::to_string(position));
  }

  std::string emptyLine(LINE_LENGTH - 1, ' ');

  file << emptyLine << '\n';
  if (file.fail()) {
    throw std::runtime_error("Failed to write empty line at index: " + std::to_string(index));
  }

  file.close();
}
} // namespace server
