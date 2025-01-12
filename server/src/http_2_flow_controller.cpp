#include "include/http_2_flow_controller.h"

#include <stdexcept>

namespace server {

Http2FlowController::Http2FlowController(uint32_t initialWindowSize)
    : windowSize_(initialWindowSize)
    , initialWindowSize_(initialWindowSize) {
  if (initialWindowSize == 0) {
    throw std::invalid_argument("Initial window size must be greater than 0");
  }

  if (initialWindowSize > MAX_WINDOW_SIZE) {
    throw std::invalid_argument("Initial window size exceeds maximum stream window size");
  }
}

bool Http2FlowController::consume(uint32_t bytes) {
  uint32_t currentSize = windowSize_.load(std::memory_order_relaxed);

  do {
    if (currentSize < bytes) {
      return false;
    }

  } while (!windowSize_.compare_exchange_weak(
      currentSize,
      currentSize - bytes,
      std::memory_order_release,
      std::memory_order_relaxed
  ));

  return true;
}

bool Http2FlowController::increment(int32_t bytes) {
  if (bytes <= 0) {
    return false;
  }

  uint32_t currentSize = windowSize_.load(std::memory_order_acquire);

  do {
    if (bytes > static_cast<int32_t>(MAX_WINDOW_SIZE - currentSize)) {
      return false;
    }

    uint32_t newSize = currentSize + bytes;
    if (newSize > MAX_WINDOW_SIZE) {
      return false;
    }

  } while (!windowSize_.compare_exchange_weak(
      currentSize,
      currentSize + bytes,
      std::memory_order_release,
      std::memory_order_relaxed
  ));

  return true;
}

bool Http2FlowController::setInitSize(uint32_t newSize) {
  if (newSize > MAX_WINDOW_SIZE) {
    return false;
  }

  uint32_t oldSize = initialWindowSize_.exchange(newSize);
  int32_t diff     = static_cast<int32_t>(newSize) - static_cast<int32_t>(oldSize);

  if (diff != 0) {
    return increment(diff);
  }

  return true;
}

void Http2FlowController::reset() {
  windowSize_.store(initialWindowSize_.load(std::memory_order_relaxed), std::memory_order_release);
}

bool Http2FlowController::isWithinWindowSize(uint32_t bytes) const noexcept {
  return windowSize_.load(std::memory_order_acquire) >= bytes;
}

uint32_t Http2FlowController::windowSize() const noexcept {
  return windowSize_.load(std::memory_order_acquire);
}
} // namespace server
