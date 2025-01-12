#include "include/http_2_frame.h"

#include <stdexcept>

namespace server {

Http2Frame::Http2Frame()
    : type_(FrameType::DATA)
    , flags_(0)
    , streamId_(0)
    , length_(0) {}

Http2Frame::Http2Frame(FrameType type, uint8_t flags, uint32_t streamId)
    : type_(type)
    , flags_(flags)
    , streamId_(streamId)
    , length_(0) {}

void Http2Frame::setPayload(const std::vector<uint8_t> &payload) {
  if (payload.size() > MAX_FRAME_SIZE) {
    throw std::runtime_error("Payload size exceeds maximum frame size");
  }

  payload_ = payload;
  length_  = static_cast<uint32_t>(payload.size());
}

std::vector<uint8_t> Http2Frame::serialize() const {
  std::vector<uint8_t> frame;
  frame.reserve(9 + length_);

  frame.push_back(static_cast<uint8_t>(length_ >> 16));
  frame.push_back(static_cast<uint8_t>(length_ >> 8));
  frame.push_back(static_cast<uint8_t>(length_));

  frame.push_back(static_cast<uint8_t>(type_));

  frame.push_back(flags_);

  frame.push_back(static_cast<uint8_t>(streamId_ >> 24) & 0x7F);
  frame.push_back(static_cast<uint8_t>(streamId_ >> 16));
  frame.push_back(static_cast<uint8_t>(streamId_ >> 8));
  frame.push_back(static_cast<uint8_t>(streamId_));

  frame.insert(frame.end(), payload_.begin(), payload_.end());

  return frame;
}

Http2Frame Http2Frame::deserialize(const std::vector<uint8_t> &data) {
  if (data.size() < 9) {
    throw std::runtime_error("Invalid frame size");
  }

  Http2Frame frame;
  frame.length_   = (data[0] << 16) | (data[1] << 8) | data[2];
  frame.type_     = static_cast<FrameType>(data[3]);
  frame.flags_    = data[4];
  frame.streamId_ = (static_cast<uint32_t>(data[5] & 0x7F) << 24)
                    | (static_cast<uint32_t>(data[6]) << 16) | (static_cast<uint32_t>(data[7]) << 8)
                    | static_cast<uint32_t>(data[8]);

  if (data.size() < 9 + frame.length_) {
    throw std::runtime_error("Frame payload incomplete");
  }

  frame.payload_.assign(data.begin() + 9, data.begin() + 9 + frame.length_);

  return frame;
}

bool Http2Frame::hasFlag(Flags flag) const {
  return (flags_ & static_cast<uint8_t>(flag)) != 0;
}

void Http2Frame::setFlag(Flags flag) {
  flags_ |= static_cast<uint8_t>(flag);
}

void Http2Frame::clearFlag(Flags flag) {
  flags_ &= ~static_cast<uint8_t>(flag);
}
} // namespace server
