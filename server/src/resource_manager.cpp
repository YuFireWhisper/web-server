#include "include/resource_manager.h"

namespace server {

bool ResourceManager::addValue(size_t offset, unsigned int value) {
  auto *targetBase = reinterpret_cast<char *>(&state_);
  auto *target     = reinterpret_cast<std::atomic<unsigned int> *>(targetBase + offset);
  auto *limitBase  = reinterpret_cast<char *>(&limits_);
  auto *limit      = reinterpret_cast<unsigned int *>(limitBase + offset);

  unsigned int expected = target->load();
  while (true) {
    if (expected + value > *limit) {
      return false;
    }

    if (target->compare_exchange_weak(expected, expected + value)) {
      return true;
    }
  }

  return true;
}

bool ResourceManager::subValue(size_t offset, unsigned int value) {
  auto *targetBase = reinterpret_cast<char *>(&state_);
  auto *target     = reinterpret_cast<std::atomic<unsigned int> *>(targetBase + offset);

  unsigned int expected = target->load();
  while (true) {
    if (expected < value) {
      return false;
    }

    if (target->compare_exchange_weak(expected, expected - value)) {
      return true;
    }
  }

  return true;
}

} // namespace server
