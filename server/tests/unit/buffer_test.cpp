#include "include/buffer.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

namespace server {

class BufferTest : public ::testing::Test {
protected:
  void SetUp() override { buffer = std::make_unique<Buffer>(1024); }

  std::unique_ptr<Buffer> buffer;
};

TEST_F(BufferTest, InitializeWithValidSize) {
  Buffer buf(1024);
  EXPECT_EQ(buf.readableSize(), 0);
  EXPECT_GT(buf.writableBytes(), 0);
}

TEST_F(BufferTest, InitializeWithInvalidSizeThrows) {
  EXPECT_THROW(Buffer(-1), std::invalid_argument);
}

TEST_F(BufferTest, AppendDataIncreasesReadableBytes) {
  std::string testData = "Hello, World!";
  buffer->write(testData);
  EXPECT_EQ(buffer->readableSize(), testData.length());
}

TEST_F(BufferTest, AppendNullDataThrows) {
  EXPECT_THROW(buffer->write(nullptr, 5), std::invalid_argument);
}

TEST_F(BufferTest, RetrieveAsStringReturnsAppendedData) {
  std::string testData = "Test Data";
  buffer->write(testData);
  EXPECT_EQ(buffer->read(testData.length()), testData);
  EXPECT_EQ(buffer->readableSize(), 0);
}

TEST_F(BufferTest, RetrieveAsStringWithInvalidLengthThrows) {
  std::string testData = "Test";
  buffer->write(testData);
  EXPECT_THROW(buffer->read(testData.length() + 1), std::out_of_range);
}

TEST_F(BufferTest, RetrieveAllAsStringClearsBuffer) {
  std::string testData = "Test Data";
  buffer->write(testData);
  EXPECT_EQ(buffer->readAll(), testData);
  EXPECT_EQ(buffer->readableSize(), 0);
}

TEST_F(BufferTest, ResizeIncreasesCapacity) {
  size_t originalWritable = buffer->writableBytes();
  buffer->resize(2048);
  EXPECT_GT(buffer->writableBytes(), originalWritable);
}

TEST_F(BufferTest, ResizePreservesData) {
  std::string testData = "Test Data";
  buffer->write(testData);
  buffer->resize(2048);
  EXPECT_EQ(buffer->read(testData.length()), testData);
}

TEST_F(BufferTest, ResizeToSmallerSizeThrows) {
  std::string testData(512, 'a');
  buffer->write(testData);
  EXPECT_THROW(buffer->resize(256), std::invalid_argument);
}

TEST_F(BufferTest, AppendStringView) {
  std::string_view testView = "Test Data";
  buffer->write(testView);
  EXPECT_EQ(buffer->readAll(), std::string(testView));
}

TEST_F(BufferTest, ReadDataFromFd) {
  char testData[] = "Test Data";
  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);

  write(pipefd[1], testData, strlen(testData));
  close(pipefd[1]);

  int savedErrno    = 0;
  ssize_t readBytes = buffer->readData(pipefd[0], &savedErrno);

  EXPECT_GT(readBytes, 0);
  EXPECT_EQ(buffer->readAll(), std::string(testData));

  close(pipefd[0]);
}

TEST_F(BufferTest, ReadDataFromInvalidFd) {
  int savedErrno    = 0;
  ssize_t readBytes = buffer->readData(-1, &savedErrno);

  EXPECT_LT(readBytes, 0);
  EXPECT_NE(savedErrno, 0);
}

TEST_F(BufferTest, RetrievePartialData) {
  std::string testData = "Hello World";
  buffer->write(testData);

  EXPECT_EQ(buffer->read(5), "Hello");
  EXPECT_EQ(buffer->read(6), " World");
  EXPECT_EQ(buffer->readableSize(), 0);
}

TEST_F(BufferTest, MultipleAppends) {
  buffer->write("Hello");
  buffer->write(" ");
  buffer->write("World");

  EXPECT_EQ(buffer->readAll(), "Hello World");
}

TEST_F(BufferTest, WriteAndPeekOperations) {
  std::string testData = "Test";
  buffer->write(testData);

  EXPECT_EQ(std::string(buffer->peek(), testData.length()), testData);
  EXPECT_EQ(buffer->readableSize(), testData.length());
}

} // namespace server
