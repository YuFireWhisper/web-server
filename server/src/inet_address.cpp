#include "include/inet_address.h"

#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <stdexcept>

namespace server {

InetAddress::InetAddress(in_port_t port, bool loopbackOnly) {
  addr_ = {};

  initializeAddr(port);

  if (loopbackOnly) {
    addr_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  } else {
    addr_.sin_addr.s_addr = htonl(INADDR_ANY);
  }
}

void InetAddress::initializeAddr(in_port_t port) {
  addr_.sin_family = AF_INET;
  addr_.sin_port = htons(port);
}

InetAddress::InetAddress(const std::string &ip, in_port_t port) {
  addr_ = {};

  initializeAddr(port);

  if (::inet_pton(AF_INET, ip.c_str(), &addr_.sin_addr) <= 0) {
    throw std::invalid_argument("Invalid IP address");
  }
}

InetAddress::InetAddress(const struct sockaddr_in &addr)
    : addr_(addr) {}

std::string InetAddress::getIp() const {
  char buf[64] = {0};
  ::inet_ntop(AF_INET, &addr_.sin_addr, buf, sizeof(buf));
  return buf;
}

in_port_t InetAddress::getPort() const {
  return ::ntohs(addr_.sin_port);
}

std::string InetAddress::getIpPort() const {
  return getIp() + ":" + std::to_string(getPort());
}

bool InetAddress::resolveHostname(const std::string &hostname, InetAddress *result) {
  addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo *res = nullptr;
  if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
    return false;
  }

  sockaddr_in addr;
  memcpy(&addr, res->ai_addr, sizeof(sockaddr_in));
  addr.sin_port = 0;
  result->setSockAddr(addr);

  freeaddrinfo(res);
  return true;
}
} // namespace server
