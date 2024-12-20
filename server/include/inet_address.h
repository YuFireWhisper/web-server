#pragma once

#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

namespace server {

class InetAddress {
public:
  InetAddress(sa_family_t addressFamily, const std::string &ip, in_port_t port);
  InetAddress(sa_family_t addressFamily, in_port_t port, bool loopbackOnly = false);
  explicit InetAddress(const sockaddr_in &addr);

  [[nodiscard]] std::string getIp() const;
  [[nodiscard]] std::string getIpPort() const;
  [[nodiscard]] in_port_t getPort() const;
  [[nodiscard]] sa_family_t getAddressFamily() const;

  [[nodiscard]] const sockaddr *getSockAddr() const {
    return reinterpret_cast<const sockaddr *>(&addr_);
  }
  [[nodiscard]] socklen_t getSockLen() const { return sizeof(addr_); }

  static bool resolveHostname(const std::string &hostname, InetAddress *result);

private:
  static bool parseIpAddress(sa_family_t family, const std::string &ip, in_addr &result);
  static bool validatePort(in_port_t port);

  sockaddr_in addr_{};
};

} // namespace server
