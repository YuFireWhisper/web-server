#include "include/buffer.h"

#include "include/config_manager.h"

#include <stdexcept>

#include <sys/uio.h>

namespace server {

Buffer::Buffer(size_t initialSize) {
  size_t size = (initialSize != 0U) ? initialSize : config_.initialBufferSize;
  if (size > config_.maxBufferSize) {
    throw std::invalid_argument("Initial size exceeds maximum limit");
  }

  auto &configManager = ConfigManager::getInstance();
  auto *ctx           = static_cast<HttpContext *>(configManager.getContextByOffset(kHttpOffset));
  config_             = *ctx->conf;

  buffer_   = new char[size];
  writePos_ = config_.prependSize;
  readPos_  = config_.prependSize;
  capacity_ = size;
}

Buffer::~Buffer() {
  delete[] buffer_;
}

Buffer::Buffer(Buffer &&other) noexcept
    : config_(std::move(other.config_))
    , buffer_(other.buffer_)
    , writePos_(other.writePos_)
    , readPos_(other.readPos_)
    , capacity_(other.capacity_) {

  other.buffer_   = nullptr;
  other.capacity_ = 0;
  other.readPos_  = 0;
  other.writePos_ = 0;
}

Buffer &Buffer::operator=(Buffer &&other) noexcept {
  if (this != &other) {
    delete[] buffer_;

    buffer_   = other.buffer_;
    capacity_ = other.capacity_;
    readPos_  = other.readPos_;
    writePos_ = other.writePos_;
    config_   = std::move(other.config_);

    other.buffer_   = nullptr;
    other.capacity_ = 0;
    other.readPos_  = 0;
    other.writePos_ = 0;
  }
  return *this;
}

void Buffer::write(const char *data, size_t length) {
  if ((data == nullptr) && length > 0) {
    throw std::invalid_argument("Invalid data pointer");
  }

  ensureWritableSpace(length);
  std::copy_n(data, length, buffer_ + writePos_);
  writePos_ += length;
}

void Buffer::write(std::string_view data) {
  write(data.data(), data.size());
}

std::string_view Buffer::read(size_t length) {
  if (length > readableSize()) {
    throw std::out_of_range("Read length exceeds available data");
  }

  std::string_view result(buffer_ + readPos_, length);
  readPos_ += length;

  if (readPos_ >= writePos_) {
    readPos_  = config_.prependSize;
    writePos_ = config_.prependSize;
  }

  return result;
}

std::string_view Buffer::readAll() noexcept {
  std::string_view result(buffer_ + readPos_, readableSize());
  readPos_  = config_.prependSize;
  writePos_ = config_.prependSize;
  return result;
}

std::string_view Buffer::preview(size_t length) const {
  if (length > readableSize()) {
    throw std::out_of_range("Preview length exceeds available data");
  }
  return { buffer_ + readPos_, length };
}

void Buffer::ensureWritableSpace(size_t length) {
  if (writableSize() >= length) {
    return;
  }

  if (writableSize() + readPos_ - config_.prependSize >= length) {
    moveReadableDataToFront();
    return;
  }

  size_t newSize = capacity_;
  while (newSize - readPos_ < length + readableSize()) {
    newSize = newSize * GROWTH_NUMERATOR / GROWTH_DENOMINATOR;
  }
  resize(newSize);
}

void Buffer::moveReadableDataToFront() noexcept {
  size_t readable = readableSize();
  std::copy(buffer_ + readPos_, buffer_ + writePos_, buffer_ + config_.prependSize);
  readPos_  = config_.prependSize;
  writePos_ = readPos_ + readable;
}

void Buffer::resize(size_t newSize) {
  if (newSize > config_.maxBufferSize) {
    throw std::invalid_argument("Requested size exceeds maximum limit");
  }

  if (newSize < capacity_) {
    throw std::invalid_argument("Cannot resize: would lose data");
  }

  char *newBuffer = new char[newSize];
  size_t readable = readableSize();

  if (readable > 0) {
    std::copy_n(buffer_ + readPos_, readable, newBuffer + config_.prependSize);
  }

  delete[] buffer_;
  buffer_   = newBuffer;
  capacity_ = newSize;
  readPos_  = config_.prependSize;
  writePos_ = readPos_ + readable;
}

ssize_t Buffer::readFromFd(int fd, int *errorCode) {
  char extraBuffer[65536];
  struct iovec vec[2];

  vec[0].iov_base = buffer_ + writePos_;
  vec[0].iov_len  = writableSize();
  vec[1].iov_base = extraBuffer;
  vec[1].iov_len  = sizeof(extraBuffer);

  ssize_t result = ::readv(fd, vec, 2);
  if (result < 0) {
    *errorCode = errno;
    return result;
  }

  if (static_cast<size_t>(result) <= writableSize()) {
    writePos_ += result;
  } else {
    writePos_ = capacity_;
    write(extraBuffer, result - writableSize());
  }

  return result;
}

size_t Buffer::readableSize() const noexcept {
  return writePos_ - readPos_;
}

size_t Buffer::writableSize() const noexcept {
  return capacity_ - writePos_;
}

} // namespace server
