#include "include/inet_address.h"

#include "include/log.h"

#include <arpa/inet.h>
#include <array>
#include <netdb.h>
#include <stdexcept>

namespace server {

InetAddress::InetAddress(sa_family_t addressFamily, const std::string &ip, in_port_t port) {
  if (!validatePort(port)) {
    throw std::invalid_argument("Invalid port number");
  }

  addr_.sin_family = addressFamily;
  addr_.sin_port   = htons(port);

  if (!parseIpAddress(addressFamily, ip, addr_.sin_addr)) {
    LOG_ERROR("Invalid IP address: " + ip);
    throw std::invalid_argument("Invalid IP address");
  }
}

InetAddress::InetAddress(sa_family_t addressFamily, in_port_t port, bool loopbackOnly) {
  if (!validatePort(port)) {
    throw std::invalid_argument("Invalid port number");
  }

  addr_.sin_family      = addressFamily;
  addr_.sin_port        = htons(port);
  addr_.sin_addr.s_addr = loopbackOnly ? htonl(INADDR_LOOPBACK) : htonl(INADDR_ANY);
}

InetAddress::InetAddress(const sockaddr_in &addr)
    : addr_{ addr } {}

std::string InetAddress::getIp() const {
  std::array<char, INET_ADDRSTRLEN> buffer{};
  inet_ntop(addr_.sin_family, &addr_.sin_addr, buffer.data(), buffer.size());
  return { buffer.data() };
}

std::string InetAddress::getIpPort() const {
  return getIp() + ":" + std::to_string(getPort());
}

in_port_t InetAddress::getPort() const {
  return ntohs(addr_.sin_port);
}

sa_family_t InetAddress::getAddressFamily() const {
  return addr_.sin_family;
}

bool InetAddress::resolveHostname(const std::string &hostname, InetAddress *result) {
  addrinfo hints{};
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo *resolvedAddresses = nullptr;
  if (getaddrinfo(hostname.c_str(), nullptr, &hints, &resolvedAddresses) != 0) {
    return false;
  }

  if (result != nullptr) {
    *result = InetAddress(*reinterpret_cast<sockaddr_in *>(resolvedAddresses->ai_addr));
  }

  freeaddrinfo(resolvedAddresses);
  return true;
}

bool InetAddress::parseIpAddress(sa_family_t family, const std::string &ip, in_addr &result) {
  if (ip.empty() || ip == "*") {
    result.s_addr = htonl(INADDR_ANY);
    return true;
  }

  if (ip == "localhost") {
    result.s_addr = htonl(INADDR_LOOPBACK);
    return true;
  }

  return inet_pton(family, ip.c_str(), &result) > 0;
}

bool InetAddress::validatePort(in_port_t port) {
  return port > 0 && port <= 65535;
}

} // namespace server
