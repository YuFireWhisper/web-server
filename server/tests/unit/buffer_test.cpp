#include "include/buffer.h"

#include <gtest/gtest.h>

namespace server {
namespace {

class BufferTest : public ::testing::Test {
protected:
  Buffer buffer_;
};

TEST_F(BufferTest, InitialState) {
  EXPECT_EQ(buffer_.readableBytes(), 0);
  EXPECT_EQ(buffer_.writableBytes(), Buffer::kDefaultInitSize);
  EXPECT_EQ(buffer_.prependableBytes(), Buffer::kPrependSize);
}

TEST_F(BufferTest, AppendAndRetrieve) {
  std::string test_str = "Hello, World!";
  buffer_.append(test_str);

  EXPECT_EQ(buffer_.readableBytes(), test_str.length());
  EXPECT_EQ(buffer_.retrieveAsString(test_str.length()), test_str);
  EXPECT_EQ(buffer_.readableBytes(), 0);
}

TEST_F(BufferTest, MultipleAppendAndRetrieveAll) {
  std::string str1 = "Hello";
  std::string str2 = " World";
  buffer_.append(str1);
  buffer_.append(str2);

  EXPECT_EQ(buffer_.readableBytes(), str1.length() + str2.length());
  EXPECT_EQ(buffer_.retrieveAllAsString(), str1 + str2);
  EXPECT_EQ(buffer_.readableBytes(), 0);
}

TEST_F(BufferTest, EnsureSpace) {
  std::string large_str(Buffer::kDefaultInitSize * 2, 'x');
  buffer_.append(large_str);

  EXPECT_EQ(buffer_.readableBytes(), large_str.length());
  EXPECT_EQ(buffer_.retrieveAllAsString(), large_str);
}

TEST_F(BufferTest, PartialRetrieve) {
  std::string test_str = "Hello, World!";
  buffer_.append(test_str);

  const static int retrieveLen = 5;
  std::string part = buffer_.retrieveAsString(retrieveLen);
  EXPECT_EQ(part, "Hello");
  EXPECT_EQ(buffer_.readableBytes(), test_str.length() - 5);
  EXPECT_EQ(buffer_.retrieveAllAsString(), ", World!");
}

TEST_F(BufferTest, RetrieveAll) {
  buffer_.append("Hello");
  buffer_.retrieveAll();

  EXPECT_EQ(buffer_.readableBytes(), 0);
  EXPECT_EQ(buffer_.prependableBytes(), Buffer::kPrependSize);
}

TEST_F(BufferTest, RetrieveMoreThanAvailable) {
  buffer_.append("Hello");
  EXPECT_THROW(buffer_.retrieveAsString(10), std::out_of_range);
}

TEST_F(BufferTest, EmptyStringOperations) {
  buffer_.append("");
  EXPECT_EQ(buffer_.readableBytes(), 0);
  EXPECT_EQ(buffer_.retrieveAllAsString(), "");
}

TEST_F(BufferTest, LargeDataOperations) {

  const size_t large_size = Buffer::kDefaultInitSize * 4;
  std::string large_data(large_size, 'A');

  buffer_.append(large_data);
  EXPECT_EQ(buffer_.readableBytes(), large_size);
  EXPECT_EQ(buffer_.retrieveAllAsString(), large_data);
}

TEST_F(BufferTest, ContinuousWriteAndRead) {
  const static int numOfLoop = 100;
  for (int i = 0; i < numOfLoop; ++i) {
    std::string data = "test" + std::to_string(i);
    buffer_.append(data);
    EXPECT_EQ(buffer_.retrieveAsString(data.length()), data);
  }
  EXPECT_EQ(buffer_.readableBytes(), 0);
}

} // namespace
} // namespace server

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
