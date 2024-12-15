#include "include/buffer.h"
#include "include/config_commands.h"
#include "include/config_defaults.h"
#include "tests/unit/helpers/global_test_environment.h"

#include <array>
#include <gtest/gtest.h>

namespace server::testing {

class BufferTest : public ::testing::Test {
protected:
  void SetUp() override {}

  static constexpr size_t kDefaultTestSize = 1024;
  static constexpr size_t kLargeTestSize   = 2000;
  static constexpr const char *kTestData   = "Hello World";
};

TEST_F(BufferTest, InvalidConfigurationShouldFailValidation) {
  auto config = std::make_shared<BufferConfig>();

  config->initialSize = 0;
  EXPECT_THROW({ Buffer::postCheckConfig(config); }, std::invalid_argument);

  config->initialSize = 1024;
  config->prependSize = 0;
  EXPECT_THROW({ Buffer::postCheckConfig(config); }, std::invalid_argument);
}

TEST_F(BufferTest, NewBufferShouldHaveCorrectInitialState) {
  Buffer buffer(kDefaultTestSize);
  EXPECT_EQ(buffer.readableBytes(), 0);
  EXPECT_EQ(buffer.writableBytes(), kDefaultTestSize);
  EXPECT_EQ(buffer.prependableBytes(), Buffer::getConfig().prependSize);
}

TEST_F(BufferTest, AppendShouldAddDataCorrectly) {
  Buffer buffer(kDefaultTestSize);
  std::string testData(kTestData);

  buffer.append(testData);

  EXPECT_EQ(buffer.readableBytes(), testData.size());
  EXPECT_EQ(buffer.retrieveAsString(testData.size()), testData);
}

TEST_F(BufferTest, BufferShouldExpandWhenNeeded) {
  Buffer buffer(16);
  std::string testData(1000, 'x');

  buffer.append(testData);

  EXPECT_GE(buffer.writableBytes(), 0);
  EXPECT_EQ(buffer.readableBytes(), testData.size());
  EXPECT_EQ(buffer.retrieveAllAsString(), testData);
}

TEST_F(BufferTest, RetrieveShouldMoveReaderIndexCorrectly) {
  Buffer buffer(kDefaultTestSize);
  std::string testData(kTestData);
  buffer.append(testData);

  std::string firstPart = buffer.retrieveAsString(5);
  EXPECT_EQ(firstPart, "Hello");
  EXPECT_EQ(buffer.readableBytes(), 6);

  std::string remainingPart = buffer.retrieveAllAsString();
  EXPECT_EQ(remainingPart, " World");
  EXPECT_EQ(buffer.readableBytes(), 0);
}

TEST_F(BufferTest, ReadDataShouldHandleDifferentSizes) {
  Buffer buffer(kDefaultTestSize);

  std::array<int, 2> pipefd{};
  ASSERT_EQ(pipe(pipefd.data()), 0);

  std::string testData(kLargeTestSize, 'x');
  ssize_t written = write(pipefd[1], testData.data(), testData.size());
  ASSERT_EQ(written, static_cast<ssize_t>(testData.size()));

  int savedErrno = 0;
  ssize_t result = buffer.readData(pipefd[0], &savedErrno);

  EXPECT_EQ(result, static_cast<ssize_t>(testData.size()));
  EXPECT_EQ(buffer.readableBytes(), testData.size());
  EXPECT_EQ(buffer.retrieveAllAsString(), testData);

  close(pipefd[0]);
  close(pipefd[1]);
}

TEST_F(BufferTest, ReadDataShouldHandleErrors) {
  Buffer buffer(kDefaultTestSize);
  int savedErrno = 0;

  ssize_t result = buffer.readData(-1, &savedErrno);

  EXPECT_LT(result, 0);
  EXPECT_NE(savedErrno, 0);
  EXPECT_EQ(buffer.readableBytes(), 0);
}

TEST_F(BufferTest, RetrieveShouldThrowOnOverflow) {
  Buffer buffer(kDefaultTestSize);
  buffer.append("Hello");

  EXPECT_THROW(buffer.retrieveAsString(10), std::out_of_range);
}

TEST_F(BufferTest, HasWrittenShouldUpdateWritePosition) {
  Buffer buffer(kDefaultTestSize);
  std::string testData(kTestData);

  memcpy(buffer.beginWrite(), testData.data(), testData.size());
  buffer.hasWritten(testData.size());

  EXPECT_EQ(buffer.readableBytes(), testData.size());
  EXPECT_EQ(buffer.retrieveAllAsString(), testData);
}

} // namespace server::testing
