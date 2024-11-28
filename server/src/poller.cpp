#include "include/poller.h"

#include "include/epoll_poller.h"
#include "include/event_loop.h"

namespace server {

Poller *Poller::newDefaultPoller(EventLoop *loop) {
  return new EPollPoller(loop);
}

} // namespace server
