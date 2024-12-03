#include "include/poller.h"

#include "include/channel.h"
#include "include/epoll_poller.h"
#include "include/event_loop.h"

namespace server {

Poller::Poller(EventLoop *loop)
    : ownerLoop_(loop) {}

void Poller::assertInLoopThread() const {
  ownerLoop_->assertInLoopThread();
}

Poller *Poller::newDefaultPoller(EventLoop *loop) {
  return new EPollPoller(loop);
}

bool Poller::hasChannel(Channel *channel) const {
  if (!channel) {
    return false;
  }

  assertInLoopThread();
  auto it = channels_.find(channel->fd());
  return it != channels_.end() && it->second == channel;
}
} // namespace server
