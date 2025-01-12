#include "include/http_2_flow_controller.h"

#include <gtest/gtest.h>

namespace server {

class Http2FlowControllerTest : public ::testing::Test {
protected:
  const uint32_t kDefaultWindowSize = 65535;
  const uint32_t kMaxWindowSize     = 2147483647;
};

TEST_F(Http2FlowControllerTest, InitializationWithValidWindowSize) {
  Http2FlowController controller(kDefaultWindowSize);
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize);
}

TEST_F(Http2FlowControllerTest, InitializationWithZeroWindowSizeThrows) {
  EXPECT_THROW(Http2FlowController(0), std::invalid_argument);
}

TEST_F(Http2FlowControllerTest, InitializationWithExcessiveWindowSizeThrows) {
  EXPECT_THROW(Http2FlowController(kMaxWindowSize + 1), std::invalid_argument);
}

TEST_F(Http2FlowControllerTest, ConsumeWithinWindowSize) {
  Http2FlowController controller(kDefaultWindowSize);
  EXPECT_TRUE(controller.consume(1000));
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize - 1000);
}

TEST_F(Http2FlowControllerTest, ConsumeExceedingWindowSizeFails) {
  Http2FlowController controller(kDefaultWindowSize);
  EXPECT_FALSE(controller.consume(kDefaultWindowSize + 1));
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize);
}

TEST_F(Http2FlowControllerTest, IncrementWithinMaxLimit) {
  Http2FlowController controller(kDefaultWindowSize);
  EXPECT_TRUE(controller.increment(1000));
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize + 1000);
}

TEST_F(Http2FlowControllerTest, IncrementExceedingMaxLimitFails) {
  Http2FlowController controller(kMaxWindowSize - 100);
  EXPECT_FALSE(controller.increment(101));
  EXPECT_EQ(controller.windowSize(), kMaxWindowSize - 100);
}

TEST_F(Http2FlowControllerTest, ResizeToValidWindowSize) {
  Http2FlowController controller(kDefaultWindowSize);
  EXPECT_TRUE(controller.setInitSize(kDefaultWindowSize * 2));
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize * 2);
}

TEST_F(Http2FlowControllerTest, ResizeToExcessiveWindowSizeFails) {
  Http2FlowController controller(kDefaultWindowSize);
  EXPECT_FALSE(controller.setInitSize(kMaxWindowSize + 1));
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize);
}

TEST_F(Http2FlowControllerTest, ResetRestoresInitialWindowSize) {
  Http2FlowController controller(kDefaultWindowSize);
  controller.consume(1000);
  controller.reset();
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize);
}

TEST_F(Http2FlowControllerTest, IsWithinWindowSizeChecksCorrectly) {
  Http2FlowController controller(kDefaultWindowSize);
  EXPECT_TRUE(controller.isWithinWindowSize(kDefaultWindowSize));
  EXPECT_TRUE(controller.isWithinWindowSize(kDefaultWindowSize - 1));
  EXPECT_FALSE(controller.isWithinWindowSize(kDefaultWindowSize + 1));
}

TEST_F(Http2FlowControllerTest, ConcurrentOperations) {
  Http2FlowController controller(kDefaultWindowSize);
  std::vector<std::thread> threads;
  const int numThreads          = 100;
  const uint32_t incrementValue = 10;

  threads.reserve(numThreads);
  for (int i = 0; i < numThreads; ++i) {
    threads.emplace_back([&controller]() {
      controller.increment(incrementValue);
      controller.consume(incrementValue);
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize);
}

TEST_F(Http2FlowControllerTest, ComplexFlowScenario) {
  Http2FlowController controller(kDefaultWindowSize);

  EXPECT_TRUE(controller.consume(1000));
  EXPECT_TRUE(controller.increment(2000));
  EXPECT_TRUE(controller.setInitSize(kDefaultWindowSize + 5000));
  EXPECT_TRUE(controller.consume(3000));

  controller.reset();
  EXPECT_EQ(controller.windowSize(), kDefaultWindowSize + 5000);
}

} // namespace server
