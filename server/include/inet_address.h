#pragma once

#include "include/types.h"

#include <netinet/in.h>
#include <string>
#include <unistd.h>

#include <sys/socket.h>

namespace server {

class InetAddress {
public:
  InetAddress();
  InetAddress(const std::string &address, in_port_t port);
  explicit InetAddress(in_port_t port = 0, bool loopbackOnly = false);
  explicit InetAddress(const struct sockaddr_in &addr);

  [[nodiscard]] std::string getIp() const;
  [[nodiscard]] std::string getIpPort() const;
  [[nodiscard]] in_port_t getPort() const;

  [[nodiscard]] const sockaddr *getSockAddr() const {
    return reinterpret_cast<const sockaddr *>(&addr_);
  }
  [[nodiscard]] socklen_t getSockLen() const { return sizeof(addr_); }
  void setSockAddr(const struct sockaddr_in &addr);

  static bool resolveHostname(const std::string &hostname, InetAddress *result);

  static char *initializeAddrConfig(const ConfigPtr &conf, const std::string &value, size_t offset);
  static char *handleConfigListen(const ConfigPtr &conf, const std::string &value, size_t offset);

private:
  static bool parseAddress(const std::string &address, in_addr &result);
  static bool parsePort(const std::string &portStr, in_port_t &result);
  static bool
  parseListenValue(const std::string &value, std::string &address, std::string &portStr);

  static std::string handleNoColon(sockaddr_in *conf, const std::string &value);
  static std::string handleAddress(sockaddr_in *conf, const std::string &value);
  static std::string handlePort(sockaddr_in *conf, const std::string &value);

  sockaddr_in addr_ = {};
  static inline sockaddr_in globalConfig_{};
  static inline std::mutex configMutex_{};
  static inline bool isInitialized_ = false;
};

} // namespace server
