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

  void write(const char *data, size_t len);
  void write(std::string_view str);

  void resize(size_t newSize);
  ssize_t readData(int fd, int *savedErrno);

  std::string read(size_t len);
  std::string readAll();

  [[nodiscard]] size_t readableSize() const noexcept { return writerIndex_ - readerIndex_; }
  [[nodiscard]] size_t writableSize() const noexcept { return capacity_ - writerIndex_; }
  [[nodiscard]] size_t prependableBytes() const noexcept { return readerIndex_; }

  [[nodiscard]] char *begin() const { return buffer_; }

  [[nodiscard]] char *beginWrite() const noexcept { return begin() + writerIndex_; }

  void hasWritten(size_t len) noexcept;
  [[nodiscard]] const char *peek() const noexcept { return begin() + readerIndex_; }

  void hasRead(size_t len);
  void hasReadAll() noexcept;

  HttpConfig getConfig() { return config_; }

private:
  void ensureSpace(size_t len);
  void makeSpace(size_t len);

  HttpConfig config_;
  char *buffer_       = nullptr;
  size_t writerIndex_ = 0;
  size_t readerIndex_ = 0;
  size_t capacity_    = 0;
};

} // namespace server
