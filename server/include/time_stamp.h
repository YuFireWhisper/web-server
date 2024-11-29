#pragma once

#include <cstdint>
#include <string>

namespace server {

class TimeStamp {
public:
    static constexpr int64_t MicroSecondsPerSecond = 1000 * 1000;

    constexpr TimeStamp() noexcept : microSecondsSinceEpoch_(0) {}
    explicit constexpr TimeStamp(int64_t microSecondsSinceEpoch) noexcept 
        : microSecondsSinceEpoch_(microSecondsSinceEpoch) {}

    static TimeStamp now();
    static constexpr TimeStamp invalid() noexcept { return TimeStamp(); }

    [[nodiscard]] constexpr bool valid() const noexcept { 
        return microSecondsSinceEpoch_ > 0; 
    }
    
    [[nodiscard]] constexpr int64_t microSecondsSinceEpoch() const noexcept { 
        return microSecondsSinceEpoch_; 
    }
    
    [[nodiscard]] constexpr double secondsSinceEpoch() const noexcept {
        return static_cast<double>(microSecondsSinceEpoch_) / MicroSecondsPerSecond;
    }

    [[nodiscard]] std::string toString() const;
    [[nodiscard]] std::string toFormattedString(bool showMicroseconds = true) const;

    [[nodiscard]] constexpr TimeStamp operator+(double seconds) const noexcept {
        int64_t delta = static_cast<int64_t>(seconds * MicroSecondsPerSecond);
        return TimeStamp(microSecondsSinceEpoch_ + delta);
    }

    [[nodiscard]] constexpr TimeStamp operator-(double seconds) const noexcept {
        return operator+(-seconds);
    }

    [[nodiscard]] constexpr double operator-(const TimeStamp& rhs) const noexcept {
        int64_t diff = microSecondsSinceEpoch_ - rhs.microSecondsSinceEpoch_;
        return static_cast<double>(diff) / MicroSecondsPerSecond;
    }

    [[nodiscard]] constexpr auto operator<=>(const TimeStamp&) const noexcept = default;
    [[nodiscard]] constexpr bool operator==(const TimeStamp&) const noexcept = default;

private:
    int64_t microSecondsSinceEpoch_;
};

[[nodiscard]] constexpr TimeStamp operator+(double seconds, const TimeStamp& timestamp) noexcept {
    return timestamp + seconds;
}

} // namespace server
