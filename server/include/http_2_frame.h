#pragma once

#include <cstdint>
#include <vector>
namespace server {

enum class FrameType : uint8_t {
  DATA          = 0x0,
  HEADERS       = 0x1,
  PRIORITY      = 0x2,
  RST_STREAM    = 0x3,
  SETTINGS      = 0x4,
  PUSH_PROMISE  = 0x5,
  PING          = 0x6,
  GOAWAY        = 0x7,
  WINDOW_UPDATE = 0x8,
  CONTINUATION  = 0x9
};

enum class Flags : uint8_t {
  NONE        = 0x0,
  ACK         = 0x1,
  END_STREAM  = 0x2,
  END_HEADERS = 0x4,
  PADDED      = 0x8,
  PRIORITY    = 0x20
};

constexpr size_t MAX_FRAME_SIZE = 16384;

class Http2Frame {
public:
  Http2Frame();
  Http2Frame(FrameType type, uint8_t flags, uint32_t streamId);

  void setPayload(const std::vector<uint8_t> &payload);
  [[nodiscard]] std::vector<uint8_t> serialize() const;
  static Http2Frame deserialize(const std::vector<uint8_t> &data);

  [[nodiscard]] FrameType type() const noexcept { return type_; }
  [[nodiscard]] uint8_t flags() const noexcept { return flags_; }
  [[nodiscard]] uint32_t streamId() const noexcept { return streamId_; }
  [[nodiscard]] uint32_t length() const noexcept { return length_; }
  [[nodiscard]] const std::vector<uint8_t> &payload() const noexcept { return payload_; }

  [[nodiscard]] bool hasFlag(Flags flag) const;
  void setFlag(Flags flag);
  void clearFlag(Flags flag);

private:
  FrameType type_;
  uint8_t flags_;
  uint32_t streamId_;
  uint32_t length_;
  std::vector<uint8_t> payload_;
};

} // namespace server
