#include "include/epoll_poller.h"

#include "include/channel.h"
#include "include/log.h"
#include "include/time_stamp.h"
#include "include/types.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <stdexcept>
#include <unistd.h>

#include <sys/epoll.h>

namespace server {
EPollPoller::EPollPoller(EventLoop *loop)
    : Poller(loop)
    , epollfd_(::epoll_create1(EPOLL_CLOEXEC))
    , events_(kInitEventListSize) {
  checkCreateStatus();
}

void EPollPoller::checkCreateStatus() {
  if (epollfd_ < 0) {
    std::string message = "Create EPollPoller failed";
    Logger::log(LogLevel::FATAL, message, "epoll_poller.log");
    throw std::runtime_error(message);
  }

  Logger::log(LogLevel::INFO, "EPollPoller created with fd: " + std::to_string(epollfd_));
}

EPollPoller::~EPollPoller() {
  for (auto &pair : channels_) {
    if (pair.second->index() == static_cast<int>(PollerState::kAdded)) {
      channel_ = pair.second;
      channelFd_ = pair.first;
      update(EPOLL_CTL_DEL);
    }
  }
  channels_.clear();
  ::close(epollfd_);
}

TimeStamp EPollPoller::poll(int timeoutMs, ChannelList *activeChannels) {
  activeChannels_ = activeChannels;
  timeoutMs_ = timeoutMs;

  numEvent_ =
      ::epoll_wait(epollfd_, &*events_.begin(), static_cast<int>(events_.size()), timeoutMs);

  return checkPollStatus();
}

TimeStamp EPollPoller::checkPollStatus() {
  TimeStamp now = TimeStamp::now();

  if (hasError()) {
    handleError();
    return now;
  }

  if (hasEvents()) {
    processEvents();
  }

  return now;
}

bool EPollPoller::hasError() const {
  return numEvent_ < 0;
}

bool EPollPoller::hasEvents() const {
  return numEvent_ > 0;
}

void EPollPoller::handleError() {
  if (isInterrupted()) {
    retryPoll();
    return;
  }

  logError();
}

bool EPollPoller::isInterrupted() const {
  return errno == EINTR;
}

void EPollPoller::retryPoll() {
  poll(timeoutMs_, activeChannels_);
}

void EPollPoller::logError() {
  errno = 0;
  Logger::log(LogLevel::ERROR, "EPoll error occurred", "epoll_poller.log");
}

void EPollPoller::processEvents() {
  fillActiveChannels();
  checkEventSize();
}

void EPollPoller::checkEventSize() {
  if (static_cast<size_t>(numEvent_) == events_.size()) {
    events_.resize(events_.size() * 2);
  }
}

void EPollPoller::updateChannel(Channel *channel) {
  assertInLoopThread();

  const int fd = channel->fd();
  const int index = channel->index();

  if (fd < 0) {
    Logger::log(LogLevel::ERROR, "Invalid fd in updateChannel: " + std::to_string(fd));
    return;
  }

  channelIndex_ = index;
  channelFd_ = fd;
  channel_ = channel;

  setEventForUpdate();

  if (isNewStatus() || isDelStatus()) {
    Logger::log(
        LogLevel::DEBUG,
        "Before adding to channels_, size: " + std::to_string(channels_.size())
    );

    channels_[fd] = channel;

    Logger::log(
        LogLevel::DEBUG,
        "After adding to channels_, size: " + std::to_string(channels_.size())
            + " channel ptr: " + std::to_string((uintptr_t)channel)
    );

    channel->set_index(static_cast<int>(PollerState::kAdded));

    Logger::log(
        LogLevel::DEBUG,
        "Adding channel to channels_ map, size: " + std::to_string(channels_.size())
    );

    if (epoll_ctl(epollfd_, EPOLL_CTL_ADD, fd, &event_) < 0) {
      Logger::log(LogLevel::ERROR, "epoll_ctl add error for fd: " + std::to_string(fd));
    }
    return;
  }

  if (channel->isNoneEvent()) {
    if (index == static_cast<int>(PollerState::kAdded)) {
      if (epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, &event_) < 0) {
        Logger::log(
            LogLevel::ERROR,
            "epoll_ctl del error for fd: " + std::to_string(fd) + ": "
                + std::string(strerror(errno))
        );
      }
    }
    channel->set_index(static_cast<int>(PollerState::kDeleted));
    return;
  }

  if (index == static_cast<int>(PollerState::kAdded)) {
    if (epoll_ctl(epollfd_, EPOLL_CTL_MOD, fd, &event_) < 0) {
      Logger::log(
          LogLevel::ERROR,
          "epoll_ctl mod error for fd: " + std::to_string(fd) + ": " + std::string(strerror(errno))
      );
      return;
    }
  }
}

bool EPollPoller::isNewStatus() const {
  return channelIndex_ == static_cast<int>(PollerState::kNew);
}

bool EPollPoller::isDelStatus() const {
  return channelIndex_ == static_cast<int>(PollerState::kDeleted);
}

void EPollPoller::handleNewStatus() {
  channels_[channelFd_] = channel_;
}

void EPollPoller::setIndexToAdd() {
  channel_->set_index(static_cast<int>(PollerState::kAdded));
}

bool EPollPoller::isNoneEventChannel() const {
  return channel_->isNoneEvent();
}

void EPollPoller::handleNoneEventChannel() {
  update(EPOLL_CTL_DEL);
}

void EPollPoller::setIndexToDel() {
  channel_->set_index(static_cast<int>(PollerState::kDeleted));
}

void EPollPoller::update(int operation) {
  assert(channel_ != nullptr);
  assert(channelFd_ >= 0);
  assert(epollfd_ >= 0);

  operation_ = operation;
  event_ = {0};
  event_.events = channel_->events();
  event_.data.ptr = channel_;

  Logger::log(
      LogLevel::DEBUG,
      "Updating channel fd: " + std::to_string(channelFd_) + " operation: "
          + std::to_string(operation) + " events: " + std::to_string(channel_->events())
  );

  if (::epoll_ctl(epollfd_, operation_, channelFd_, &event_) < 0) {
    Logger::log(
        LogLevel::ERROR,
        "epoll_ctl "
            + std::string(
                operation_ == EPOLL_CTL_ADD ? "add" : (operation_ == EPOLL_CTL_DEL ? "del" : "mod")
            )
            + " error for fd: " + std::to_string(channelFd_) + ": " + std::string(strerror(errno))
    );
  }
}

void EPollPoller::updateWithEpollCtl() {
  updateReturnVal_ = ::epoll_ctl(epollfd_, operation_, channelFd_, &event_);
}

void EPollPoller::setEventForUpdate() {
  event_ = {0};
  event_.events = channel_->events();
  event_.data.ptr = channel_;

  Logger::log(
      LogLevel::DEBUG,
      "Setting event for fd = " + std::to_string(channelFd_) + " events = "
          + std::to_string(event_.events) + " index = " + std::to_string(channelIndex_)
  );
}

bool EPollPoller::isUpdateFailed() const {
  return updateReturnVal_ < 0;
}

void EPollPoller::handleUpdateFailed() {
  if (isDelStatus()) {
    logForDelOperation();
    return;
  }

  handleNotDelOperation();
}

void EPollPoller::logForDelOperation() {
  std::string message = "epoll_ctl del error: " + std::string(strerror(errno));
  Logger::log(LogLevel::ERROR, message, "epoll_poller.log");
}

void EPollPoller::handleNotDelOperation() {
  std::string message = "epoll_ctl error: " + std::string(strerror(errno));
  Logger::log(LogLevel::FATAL, message, "epoll_poller.log");
  throw std::runtime_error(message);
}

void EPollPoller::removeChannel(Channel *channel) {
  int fd = channel->fd();
  if (!hasChannel(channel)) {
    return;
  }

  channelFd_ = fd;
  channel_ = channel;

  if (channel->index() == static_cast<int>(PollerState::kAdded)) {
    update(EPOLL_CTL_DEL);
  }

  eraseChannel();
  setIndexToNew();
}

void EPollPoller::eraseChannel() {
  channels_.erase(channelFd_);
}

void EPollPoller::setIndexToNew() {
  channel_->set_index(static_cast<int>(PollerState::kNew));
}

void EPollPoller::fillActiveChannels() {
  for (int i = 0; i < numEvent_; ++i) {
    channel_ = static_cast<Channel *>(events_[i].data.ptr);
    channel_->set_revents(events_[i].events);
    activeChannels_->push_back(channel_);
  }
}
} // namespace server
