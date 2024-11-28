#include "include/time_stamp.h"

#include <functional>
namespace server {
class Timer {
public:
  using TimerCallback = std::function<void()>;

  Timer(TimerCallback cb, TimeStamp when, double interval)
        : callback_(std::move(cb))
        , expiration_(when)
        , interval_(interval)
        , repeat_(interval > 0.0) {}  void run() {
    callback_();
  }

  TimeStamp expiration() const {
    return expiration_;
  }
  bool repeat() const {
    return repeat_;
  }
  double interval() const {
    return interval_;
  }

private:
  const TimerCallback callback_;
  TimeStamp expiration_;
  const double interval_;
  const bool repeat_;
};
} // namespace server
