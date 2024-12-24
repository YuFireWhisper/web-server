#pragma once

#include "include/config_defaults.h"

#include <cstddef>
#include <string_view>

#include <sys/types.h>

namespace server {

class Buffer {
public:
  explicit Buffer(size_t initialSize = 0);
  ~Buffer();

  Buffer(Buffer &&other) noexcept;
  Buffer &operator=(Buffer &&other) noexcept;

  Buffer(const Buffer &)            = delete;
  Buffer &operator=(const Buffer &) = delete;

  void write(const char *data, size_t len);
  void write(std::string_view data);

  std::string_view read(size_t length);
  std::string_view readAll() noexcept;
  [[nodiscard]] std::string_view preview(size_t length) const;

  ssize_t readFromFd(int fd, int *errorCode);

  void resize(size_t newSize);
  [[nodiscard]] size_t readableSize() const noexcept;
  [[nodiscard]] size_t writableSize() const noexcept;

private:
  static constexpr size_t GROWTH_NUMERATOR   = 3;
  static constexpr size_t GROWTH_DENOMINATOR = 2;

  void ensureWritableSpace(size_t len);
  void moveReadableDataToFront() noexcept;

  HttpConfig config_;
  char *buffer_;
  size_t writePos_;
  size_t readPos_;
  size_t capacity_;
};

} // namespace server
