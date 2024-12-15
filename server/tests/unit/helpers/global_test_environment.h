#include <gtest/gtest.h>

namespace server::testing {

class GlobalTestEnvironment : public ::testing::Environment {
public:
  void SetUp() override { initialBufferByDefault(); }

  void TearDown() override {}

  static GlobalTestEnvironment *getInstance() { return new GlobalTestEnvironment(); }

private:
  GlobalTestEnvironment() = default;
  static void initialBufferByDefault();
};

} // namespace server::testing
