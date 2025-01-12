#include "include/http_2_frame.h"

#include <gtest/gtest.h>

namespace server {
namespace {

class Http2FrameTest : public ::testing::Test {
protected:
  static std::vector<uint8_t> CreateSamplePayload(size_t size) {
    return std::vector<uint8_t>(size, 0x42);
  }
};

TEST_F(Http2FrameTest, DefaultConstructorInitializesCorrectly) {
  Http2Frame frame;

  EXPECT_EQ(frame.type(), FrameType::DATA);
  EXPECT_EQ(frame.flags(), 0);
  EXPECT_EQ(frame.streamId(), 0);
  EXPECT_EQ(frame.length(), 0);
  EXPECT_TRUE(frame.payload().empty());
}

TEST_F(Http2FrameTest, ParameterizedConstructorInitializesCorrectly) {
  Http2Frame frame(FrameType::HEADERS, 0x1, 123);

  EXPECT_EQ(frame.type(), FrameType::HEADERS);
  EXPECT_EQ(frame.flags(), 0x1);
  EXPECT_EQ(frame.streamId(), 123);
  EXPECT_EQ(frame.length(), 0);
  EXPECT_TRUE(frame.payload().empty());
}

TEST_F(Http2FrameTest, SetPayloadStoresDataCorrectly) {
  Http2Frame frame;
  auto payload = CreateSamplePayload(100);

  frame.setPayload(payload);

  EXPECT_EQ(frame.payload(), payload);
  EXPECT_EQ(frame.length(), payload.size());
}

TEST_F(Http2FrameTest, SetPayloadThrowsOnExceedingMaxSize) {
  Http2Frame frame;
  auto payload = CreateSamplePayload(MAX_FRAME_SIZE + 1);

  EXPECT_THROW(frame.setPayload(payload), std::runtime_error);
}

TEST_F(Http2FrameTest, SerializeProducesValidFrame) {
  Http2Frame frame(FrameType::HEADERS, 0x5, 123);
  auto payload = CreateSamplePayload(100);
  frame.setPayload(payload);

  auto serialized = frame.serialize();

  ASSERT_EQ(serialized.size(), 9 + payload.size());
  EXPECT_EQ((serialized[0] << 16) | (serialized[1] << 8) | serialized[2], payload.size());
  EXPECT_EQ(serialized[3], static_cast<uint8_t>(FrameType::HEADERS));
  EXPECT_EQ(serialized[4], 0x5);
  EXPECT_EQ(
      (static_cast<uint32_t>(serialized[5] & 0x7F) << 24)
          | (static_cast<uint32_t>(serialized[6]) << 16)
          | (static_cast<uint32_t>(serialized[7]) << 8) | static_cast<uint32_t>(serialized[8]),
      123
  );
}

TEST_F(Http2FrameTest, DeserializeCreatesCorrectFrame) {
  Http2Frame original(FrameType::PING, 0x1, 456);
  auto payload = CreateSamplePayload(100);
  original.setPayload(payload);

  auto serialized   = original.serialize();
  auto deserialized = Http2Frame::deserialize(serialized);

  EXPECT_EQ(deserialized.type(), original.type());
  EXPECT_EQ(deserialized.flags(), original.flags());
  EXPECT_EQ(deserialized.streamId(), original.streamId());
  EXPECT_EQ(deserialized.length(), original.length());
  EXPECT_EQ(deserialized.payload(), original.payload());
}

TEST_F(Http2FrameTest, DeserializeThrowsOnInvalidSize) {
  std::vector<uint8_t> invalidData(8, 0);

  EXPECT_THROW(Http2Frame::deserialize(invalidData), std::runtime_error);
}

TEST_F(Http2FrameTest, DeserializeThrowsOnIncompletePayload) {
  Http2Frame frame(FrameType::DATA, 0, 1);
  frame.setPayload(CreateSamplePayload(100));
  auto serialized = frame.serialize();
  serialized.resize(50);

  EXPECT_THROW(Http2Frame::deserialize(serialized), std::runtime_error);
}

TEST_F(Http2FrameTest, FlagOperationsWorkCorrectly) {
  Http2Frame frame;

  frame.setFlag(Flags::END_STREAM);
  EXPECT_TRUE(frame.hasFlag(Flags::END_STREAM));
  EXPECT_FALSE(frame.hasFlag(Flags::ACK));

  frame.setFlag(Flags::PRIORITY);
  EXPECT_TRUE(frame.hasFlag(Flags::END_STREAM));
  EXPECT_TRUE(frame.hasFlag(Flags::PRIORITY));

  frame.clearFlag(Flags::END_STREAM);
  EXPECT_FALSE(frame.hasFlag(Flags::END_STREAM));
  EXPECT_TRUE(frame.hasFlag(Flags::PRIORITY));
}

TEST_F(Http2FrameTest, StreamIdHandlesMaxValue) {
  const uint32_t maxStreamId = 0x7FFFFFFF;
  Http2Frame frame(FrameType::DATA, 0, maxStreamId);

  auto serialized   = frame.serialize();
  auto deserialized = Http2Frame::deserialize(serialized);

  EXPECT_EQ(deserialized.streamId(), maxStreamId);
}

} // namespace
} // namespace server
