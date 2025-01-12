#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>

namespace server {

constexpr uint32_t MAX_WINDOW_SIZE = 2147483647; // 2^31 - 1

class Http2FlowController {
public:
  explicit Http2FlowController(uint32_t initialWindowSize);

  bool consume(uint32_t bytes);
  bool increment(int32_t bytes);

  bool setInitSize(uint32_t newSize);
  void reset();

  [[nodiscard]] bool isWithinWindowSize(uint32_t bytes) const noexcept;
  [[nodiscard]] uint32_t windowSize() const noexcept;

private:
  std::atomic<uint32_t> windowSize_;
  std::atomic<uint32_t> initialWindowSize_;
  std::mutex mutex_;
};

} // namespace server
