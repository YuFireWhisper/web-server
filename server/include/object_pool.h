#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <mutex>
namespace server {

template <typename T, size_t BlockSize = 4096>
class ObjectPool {
  static_assert(BlockSize >= sizeof(T), "BlockSize must be >= sizeof(T)");

public:
  ObjectPool(size_t initialSize = 1024) { reserve(initialSize); }

  ~ObjectPool() {
    Block *current = pool_.blocks;
    while (current != nullptr) {
      Block *next = current->next;
      delete current;
      current = next;
    }
  }

  template <typename... Args>
  [[nodiscard]] T *acquire(Args &&...args) {
    std::lock_guard lock(pool_.mutex);

    if (pool_.freeList == nullptr) {
      allocateBlock();
    }

    Node *node     = pool_.freeList;
    pool_.freeList = node->next;

    T *obj = new (node) T(std::forward<Args>(args)...);
    pool_.used.fetch_add(1, std::memory_order_relaxed);
    return obj;
  }

  void release(T *obj) {
    if (obj == nullptr) {
      return;
    }

    obj->~T();

    Node *node = reinterpret_cast<Node *>(obj);

    {
      std::lock_guard lock(pool_.mutex);
      node->next     = pool_.freeList;
      pool_.freeList = node;
      pool_.used.fetch_sub(1, std::memory_order_relaxed);
    }
  }

  void reserve(size_t count) {
    while (count > 0) {
      allocateBlock();
      count -= BlockSize / sizeof(T);
    }
  }

  [[nodiscard]] size_t used() const { return pool_.used.load(std::memory_order_relaxed); }

private:
  struct alignas(std::max_align_t) Block {
    std::array<std::byte, BlockSize> data;
    Block *next = nullptr;
  };

  struct Node {
    Node *next = nullptr;
  };

  struct Pool {
    Block *block             = nullptr;
    Node *freeList           = nullptr;
    std::atomic<size_t> used = 0;
    std::mutex mutex;
  };

  void allocateBlock() {
    std::lock_guard lock(pool_.mutex);
    auto *newBlock = new Block();
    newBlock->next = pool_.blocks;
    pool_.blocks   = newBlock;

    char *start  = reinterpret_cast<char *>(newBlock->data.data());
    size_t count = BlockSize / sizeof(T);

    for (size_t i = 0; i < count; ++i) {
      Node *node     = reinterpret_cast<Node *>(start + (i * sizeof(T)));
      node->next     = pool_.freeList;
      pool_.freeList = node;
    }
  }

  Pool pool_;
};

} // namespace server
