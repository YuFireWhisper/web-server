#pragma once

#include "include/config_defaults.h"

#include <atomic>

namespace server {

struct ResourceState {
  std::atomic<unsigned int> events         = 0;
  std::atomic<unsigned int> requests       = 0;
  std::atomic<unsigned int> connections    = 0;
  std::atomic<unsigned int> maxRequestRate = 0;
  std::atomic<unsigned int> cpu            = 0;
  std::atomic<unsigned int> memory         = 0;
};

struct ResourceLimits {
  unsigned int maxEvents         = 0;
  unsigned int maxRequests       = 0;
  unsigned int maxConnections    = 0;
  unsigned int maxRequestRate    = 0;
  unsigned int maxCpu            = 0;
  unsigned int maxMemory         = 0;
};

const size_t kResourceEventOffset    = OFFSET_OF(ResourceState, events);
const size_t kResourceRequests       = OFFSET_OF(ResourceState, requests);
const size_t kResourceConnections    = OFFSET_OF(ResourceState, connections);
const size_t kResourceMaxRequestRate = OFFSET_OF(ResourceState, maxRequestRate);
const size_t kResourceCpu            = OFFSET_OF(ResourceState, cpu);
const size_t kResourceMemory         = OFFSET_OF(ResourceState, memory);

const size_t kResourceMaxEventsOffset         = OFFSET_OF(ResourceLimits, maxEvents);
const size_t kResourceMaxRequestsOffset       = OFFSET_OF(ResourceLimits, maxRequests);
const size_t kResourceMaxConnectionsOffset    = OFFSET_OF(ResourceLimits, maxConnections);
const size_t kResourceMaxRequestRateOffset    = OFFSET_OF(ResourceLimits, maxRequestRate);
const size_t kResourceMaxCpuOffset            = OFFSET_OF(ResourceLimits, maxCpu);
const size_t kResourceMaxMemoryOffset         = OFFSET_OF(ResourceLimits, maxMemory);

class ResourceManager {
public:
  ResourceManager(ResourceLimits limits)
      : state_(ResourceState()), limits_(limits) {}

  bool addValue(size_t offset, unsigned int value);
  bool subValue(size_t offset, unsigned int value);

private:
  ResourceState state_;
  ResourceLimits limits_;
};
} // namespace server
