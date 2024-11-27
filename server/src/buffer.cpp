#include "include/buffer.h"

#include "include/log.h"

#include <algorithm>
#include <cassert>

#ifndef PROJECT_ROOT
#define PROJECT_ROOT "."
#endif

namespace server {

Buffer::Buffer(size_t initSize)
    : buffer_(PREPEND_SIZE + initSize), readerIndex_(PREPEND_SIZE), writerIndex_(PREPEND_SIZE) {}

void Buffer::append(std::string_view data) {
  Buffer::append(data.data(), data.size());
}

void Buffer::append(const char *data, size_t len) {
  ensureSpace(len);
  std::copy_n(data, len, beginWrite());
  hasWritten(len);
}

void Buffer::ensureSpace(size_t len) {
  if (writableBytes() < len) {
    makeSpace(len);
  }
  if (writableBytes() < len) {
    Logger::log(LogLevel::ERROR, "Failed to ensure space in buffer", "buffer.log");
    throw std::runtime_error("Failed to ensure space in buffer");
  }
}

void Buffer::makeSpace(size_t len) {
  if (writableBytes() + prependableBytes() < len + PREPEND_SIZE) {
    buffer_.resize(writerIndex_ + len);
  } else {
    size_t readable = readableBytes();
    std::copy(data() + readerIndex_, data() + writerIndex_, data() + PREPEND_SIZE);

    readerIndex_ = PREPEND_SIZE;
    writerIndex_ = readerIndex_ + readable;
  }
}

void Buffer::hasWritten(size_t len) noexcept {
  writerIndex_ += len;
}

std::string Buffer::retrieveAsString(size_t len) {
  if (len > readableBytes()) {
    Logger::log(LogLevel::ERROR, "Not enough data in buffer", "buffer.log");
    throw std::out_of_range("Not enough data in buffer");
  }
  std::string result(peek(), len);
  retrieve(len);
  return result;
}

void Buffer::retrieve(size_t len) {
  if (len > readableBytes()) {
    retrieveAll();
  } else {
    readerIndex_ += len;
  }
}

void Buffer::retrieveAll() noexcept {
  readerIndex_ = PREPEND_SIZE;
  writerIndex_ = PREPEND_SIZE;
}

std::string Buffer::retrieveAllAsString() {
  std::string result(peek(), readableBytes());
  retrieveAll();
  return result;
}

} // namespace server
