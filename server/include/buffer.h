#pragma once

#include "include/config_defaults.h"

#include <cstddef>
#include <string>
#include <string_view>

#include <sys/types.h>

namespace server {

class Buffer {
public:
  explicit Buffer(size_t len = 0);
  ~Buffer();

  Buffer(Buffer &&other) noexcept;
  Buffer &operator=(Buffer &&other) noexcept;

  void append(const char *data, size_t len);
  void append(std::string_view str);

  void resize(size_t newSize);
  ssize_t readData(int fd, int *savedErrno);

  std::string retrieveAsString(size_t len);
  std::string retrieveAllAsString();

  [[nodiscard]] size_t readableBytes() const noexcept { return writerIndex_ - readerIndex_; }
  [[nodiscard]] size_t writableBytes() const noexcept { return capacity_ - writerIndex_; }
  [[nodiscard]] size_t prependableBytes() const noexcept { return readerIndex_; }

  [[nodiscard]] char *begin() const { return buffer_; }

  [[nodiscard]] char *beginWrite() const noexcept { return begin() + writerIndex_; }

  void hasWritten(size_t len) noexcept;
  [[nodiscard]] const char *peek() const noexcept { return begin() + readerIndex_; }

  void retrieve(size_t len);
  void retrieveAll() noexcept;

  HttpConfig getConfig() { return config_; }

private:
  void ensureSpace(size_t len);
  void makeSpace(size_t len);

  static void checkInitialArg(size_t size, const std::string &argName);
  static void checkConfig(const ServerConfig &config);

  HttpConfig config_;
  char *buffer_       = nullptr;
  size_t writerIndex_ = 0;
  size_t readerIndex_ = 0;
  size_t capacity_    = 0;
};

} // namespace server
