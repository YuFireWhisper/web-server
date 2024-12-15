#include "tests/unit/helpers/global_test_environment.h"

#include <gtest/gtest.h>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::AddGlobalTestEnvironment(server::testing::GlobalTestEnvironment::getInstance());
  return RUN_ALL_TESTS();
}
