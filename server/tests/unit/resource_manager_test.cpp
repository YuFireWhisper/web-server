#include "include/resource_manager.h"

#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace server::testing {

class ResourceManagerTest : public ::testing::Test {
protected:
  void SetUp() override {
    limits_.maxEvents      = 1000;
    limits_.maxRequests    = 500;
    limits_.maxConnections = 100;
    limits_.maxRequestRate = 50;
    limits_.maxCpu         = 80;
    limits_.maxMemory      = 1024;
    manager_               = std::make_unique<ResourceManager>(limits_);
  }

  ResourceLimits limits_;
  std::unique_ptr<ResourceManager> manager_;
};

TEST_F(ResourceManagerTest, AddValueSucceedsWhenUnderLimit) {
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, 500));
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, 499));
}

TEST_F(ResourceManagerTest, AddValueFailsWhenExceedingLimit) {
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, 500));
  EXPECT_FALSE(manager_->addValue(kResourceEventOffset, 501));
}

TEST_F(ResourceManagerTest, SubValueSucceedsWhenSufficientValue) {
  EXPECT_TRUE(manager_->addValue(kResourceRequests, 100));
  EXPECT_TRUE(manager_->subValue(kResourceRequests, 50));
}

TEST_F(ResourceManagerTest, SubValueFailsWhenInsufficientValue) {
  EXPECT_TRUE(manager_->addValue(kResourceRequests, 30));
  EXPECT_FALSE(manager_->subValue(kResourceRequests, 50));
}

TEST_F(ResourceManagerTest, AddValueHandlesZeroCorrectly) {
  EXPECT_TRUE(manager_->addValue(kResourceCpu, 0));
}

TEST_F(ResourceManagerTest, SubValueHandlesZeroCorrectly) {
  EXPECT_TRUE(manager_->subValue(kResourceCpu, 0));
}

TEST_F(ResourceManagerTest, HandlesAllResourceTypesCorrectly) {
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, 100));
  EXPECT_TRUE(manager_->addValue(kResourceRequests, 100));
  EXPECT_TRUE(manager_->addValue(kResourceConnections, 50));
  EXPECT_TRUE(manager_->addValue(kResourceMaxRequestRate, 25));
  EXPECT_TRUE(manager_->addValue(kResourceCpu, 40));
  EXPECT_TRUE(manager_->addValue(kResourceMemory, 512));
}

TEST_F(ResourceManagerTest, ConcurrentOperationsAreThreadSafe) {
  const int numThreads          = 10;
  const int operationsPerThread = 100;
  std::vector<std::thread> threads;

  threads.reserve(numThreads);
  for (int i = 0; i < numThreads; ++i) {
    threads.emplace_back([this]() {
      for (int j = 0; j < operationsPerThread; ++j) {
        manager_->addValue(kResourceEventOffset, 1);
        manager_->subValue(kResourceEventOffset, 1);
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, 1));
  EXPECT_TRUE(manager_->subValue(kResourceEventOffset, 1));
}

TEST_F(ResourceManagerTest, AddValueRespectsLimitsUnderLoad) {
  const int value = static_cast<int>(limits_.maxEvents) / 4;
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, value));
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, value));
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, value));
  EXPECT_TRUE(manager_->addValue(kResourceEventOffset, value));
  EXPECT_FALSE(manager_->addValue(kResourceEventOffset, 1));
}

TEST_F(ResourceManagerTest, SubValueMaintainsNonNegativity) {
  EXPECT_TRUE(manager_->addValue(kResourceMemory, 100));
  EXPECT_TRUE(manager_->subValue(kResourceMemory, 50));
  EXPECT_TRUE(manager_->subValue(kResourceMemory, 50));
  EXPECT_FALSE(manager_->subValue(kResourceMemory, 1));
}

} // namespace server::testing
