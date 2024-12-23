#include "include/buffer.h"
#include "include/types.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

namespace server {

class BufferTest : public ::testing::Test {
protected:
  void SetUp() override { buffer = std::make_unique<Buffer>(); }

  void TearDown() override { buffer.reset(); }

  std::unique_ptr<Buffer> buffer;
};

TEST_F(BufferTest, InitialStateIsEmpty) {
  EXPECT_EQ(buffer->readableSize(), 0);
  EXPECT_GT(buffer->writableSize(), 0);
}

TEST_F(BufferTest, ConstructorWithCustomSize) {
  const size_t requestedSize = 1024;
  Buffer customBuffer(requestedSize);
  EXPECT_EQ(customBuffer.readableSize(), 0);
  EXPECT_EQ(customBuffer.writableSize(), requestedSize - 8);
}

TEST_F(BufferTest, ConstructorThrowsOnExcessiveSize) {
  const size_t max_size = std::numeric_limits<size_t>::max();
  EXPECT_THROW(Buffer varname(max_size), std::invalid_argument);
}

TEST_F(BufferTest, MoveConstructorTransfersOwnership) {
  buffer->write("test", 4);
  Buffer movedBuffer(std::move(*buffer));

  EXPECT_EQ(movedBuffer.readableSize(), 4);
  EXPECT_EQ(buffer->readableSize(), 0);
  EXPECT_EQ(buffer->writableSize(), 0);
}

TEST_F(BufferTest, MoveAssignmentTransfersOwnership) {
  buffer->write("test", 4);
  Buffer otherBuffer;
  otherBuffer = std::move(*buffer);

  EXPECT_EQ(otherBuffer.readableSize(), 4);
  EXPECT_EQ(buffer->readableSize(), 0);
  EXPECT_EQ(buffer->writableSize(), 0);
}

TEST_F(BufferTest, WriteAndReadString) {
  std::string_view testData = "Hello, World!";
  buffer->write(testData);

  EXPECT_EQ(buffer->readableSize(), testData.size());
  EXPECT_EQ(buffer->read(testData.size()), testData);
  EXPECT_EQ(buffer->readableSize(), 0);
}

TEST_F(BufferTest, WriteAndReadMultipleStrings) {
  buffer->write("First");
  buffer->write("Second");

  EXPECT_EQ(buffer->read(5), "First");
  EXPECT_EQ(buffer->read(6), "Second");
}

TEST_F(BufferTest, WriteNullPointerThrows) {
  EXPECT_THROW(buffer->write(nullptr, 5), std::invalid_argument);
}

TEST_F(BufferTest, ReadExceedingSizeThrows) {
  buffer->write("test", 4);
  EXPECT_THROW(buffer->read(5), std::out_of_range);
}

TEST_F(BufferTest, PreviewDoesNotModifyBuffer) {
  std::string_view testData = "test data";
  buffer->write(testData);

  auto preview = buffer->preview(4);
  EXPECT_EQ(preview, "test");
  EXPECT_EQ(buffer->readableSize(), testData.size());
}

TEST_F(BufferTest, ReadAllClearsBuffer) {
  std::string_view testData = "test data";
  buffer->write(testData);

  auto result = buffer->readAll();
  EXPECT_EQ(result, testData);
  EXPECT_EQ(buffer->readableSize(), 0);
}

TEST_F(BufferTest, AutomaticBufferGrowth) {
  std::string largeData(1000, 'A');
  buffer->write(largeData);

  EXPECT_EQ(buffer->readableSize(), 1000);
  EXPECT_EQ(buffer->readAll(), largeData);
}

TEST_F(BufferTest, ResizeIncreasesCapacity) {
  size_t newSize = 2048;
  buffer->resize(newSize);

  EXPECT_EQ(buffer->writableSize(), newSize - 8);
  EXPECT_EQ(buffer->readableSize(), 0);
}

TEST_F(BufferTest, ResizePreservesData) {
  std::string_view testData = "test data";
  buffer->write(testData);

  buffer->resize(2048);
  EXPECT_EQ(buffer->readableSize(), testData.size());
  EXPECT_EQ(buffer->readAll(), testData);
}

TEST_F(BufferTest, ResizeThrowsOnDataLoss) {
  buffer->write("test data");
  EXPECT_THROW(buffer->resize(4), std::invalid_argument);
}

TEST_F(BufferTest, ReadFromFdHandlesPartialRead) {
  int pipeFds[2];
  ASSERT_EQ(pipe(pipeFds), 0);

  std::string testData(100, 'X');
  ASSERT_EQ(write(pipeFds[1], testData.data(), testData.size()), 100);

  int errorCode     = 0;
  ssize_t bytesRead = buffer->readFromFd(pipeFds[0], &errorCode);

  EXPECT_EQ(bytesRead, 100);
  EXPECT_EQ(buffer->readableSize(), 100);
  EXPECT_EQ(buffer->readAll(), testData);

  close(pipeFds[0]);
  close(pipeFds[1]);
}

TEST_F(BufferTest, ReadFromFdHandlesError) {
  int errorCode  = 0;
  ssize_t result = buffer->readFromFd(-1, &errorCode);

  EXPECT_EQ(result, -1);
  EXPECT_NE(errorCode, 0);
}

TEST_F(BufferTest, ReadFromFdWithLargeData) {
  int pipeFds[2];
  ASSERT_EQ(pipe(pipeFds), 0);

  const size_t CHUNK_SIZE = 8 * kKib;
  std::string largeData(128 * kKib, 'Y');
  size_t totalWritten = 0;

  while (totalWritten < largeData.size()) {
    size_t remainingToWrite = largeData.size() - totalWritten;
    size_t chunkSize        = std::min(CHUNK_SIZE, remainingToWrite);

    ssize_t written = write(pipeFds[1], largeData.data() + totalWritten, chunkSize);
    ASSERT_GT(written, 0);
    totalWritten += written;

    int errorCode     = 0;
    ssize_t bytesRead = buffer->readFromFd(pipeFds[0], &errorCode);
    ASSERT_GT(bytesRead, 0);
  }

  std::string_view result = buffer->readAll();

  size_t yCount = 0;
  for (char c : result) {
    if (c == 'Y') {
      yCount++;
    }
  }

  EXPECT_GE(yCount, largeData.size());

  close(pipeFds[0]);
  close(pipeFds[1]);
}

} // namespace server
