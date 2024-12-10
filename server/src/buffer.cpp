#include "include/buffer.h"

#include "include/log.h"

#include <algorithm>
#include <bits/types/struct_iovec.h>
#include <cassert>

#include <sys/types.h>
#include <sys/uio.h>

#ifndef PROJECT_ROOT
#define PROJECT_ROOT "."
#endif

namespace server {

Buffer::Buffer(size_t initSize)
    : buffer_(kPrependSize + initSize)
    , readerIndex_(kPrependSize)
    , writerIndex_(kPrependSize) {}

void Buffer::append(std::string_view str) {
  Buffer::append(str.data(), str.size());
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
  if (writableBytes() + prependableBytes() < len + kPrependSize) {
    buffer_.resize(writerIndex_ + len + (kExtraBufferSize / 2));
  } else {
    size_t readable = readableBytes();
    std::copy(data() + readerIndex_, data() + writerIndex_, data() + kPrependSize);

    readerIndex_ = kPrependSize;
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
  readerIndex_ = kPrependSize;
  writerIndex_ = kPrependSize;
}

std::string Buffer::retrieveAllAsString() {
  std::string result(peek(), readableBytes());
  retrieveAll();
  return result;
}

ssize_t Buffer::readData(int fd, int *savedErrno) {
  std::array<char, kExtraBufferSize> extraBuffer;
  std::array<iovec, 2> vec;

  const size_t writable = writableBytes();

  vec[0].iov_base = beginWrite();
  vec[0].iov_len = writable;
  vec[1].iov_base = extraBuffer.data();
  vec[1].iov_len = sizeof(extraBuffer);

  const ssize_t result = ::readv(fd, vec.data(), 2);

  if (result < 0) {
    *savedErrno = errno;
  } else if (static_cast<size_t>(result) <= writable) {
    writerIndex_ += result;
  } else {
    writerIndex_ = buffer_.size();
    append(extraBuffer.data(), result - writable);
  }

  return result;
}

} // namespace server
