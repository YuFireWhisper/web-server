#include "include/inet_address.h"

#include "include/config_defaults.h"
#include "include/types.h"

#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>

#include <sys/socket.h>

namespace server {

char *InetAddress::initializeAddrConfig(
    const ConfigPtr &conf [[maybe_unused]],
    const std::string &value [[maybe_unused]],
    size_t offset [[maybe_unused]]
) {
  std::lock_guard<std::mutex> lock(configMutex_);

  try {
    auto *config = static_cast<ServerConfig *>(conf.get());

    if (config == nullptr) {
      return strdup("Invalid configuration pointer");
    }

    globalConfig_            = {};
    globalConfig_.sin_family = config->AddressFamily;
    globalConfig_.sin_port   = htons(config->port);

    if (inet_pton(config->AddressFamily, config->ip.c_str(), &globalConfig_.sin_addr) <= 0) {
      return strdup("Failed to parse IP address");
    }

    isInitialized_ = true;

    return nullptr;
  } catch (const std::exception &e) {
    return strdup(e.what());
  }
}

char *InetAddress::handleConfigListen(
    const ConfigPtr &conf [[maybe_unused]],
    const std::string &value,
    size_t offset [[maybe_unused]]
) {
  std::lock_guard<std::mutex> lock(configMutex_);

  try {
    std::string address;
    std::string portStr;
    if (!parseListenValue(value, address, portStr)) {
      return strdup("Invalid listen value format");
    }

    sockaddr_in newConfig{};
    newConfig.sin_family = AF_INET;

    if (!address.empty() && address != "*") {
      if (!parseAddress(address, newConfig.sin_addr)) {
        return strdup("Invalid IP address format");
      }
    } else {
      newConfig.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    in_port_t port;
    if (!parsePort(portStr, port)) {
      return strdup("Invalid port number");
    }
    newConfig.sin_port = htons(port);

    globalConfig_  = newConfig;
    isInitialized_ = true;

    return nullptr;
  } catch (const std::exception &e) {
    return strdup(e.what());
  }
}

std::string InetAddress::handlePort(sockaddr_in *conf, const std::string &value) {
  int port = std::stoi(value);
  if (port < 0 || port > 65535) {
    std::string message = "Invalid port! Port: " + value;
    return message;
  }

  conf->sin_port = port;

  return "";
}

bool InetAddress::parseListenValue(
    const std::string &value,
    std::string &address,
    std::string &portStr
) {
  size_t colonPos = value.find(':');
  if (colonPos == std::string::npos) {
    address = "*";
    portStr = value;
  } else {
    address = value.substr(0, colonPos);
    portStr = value.substr(colonPos + 1);
  }
  return true;
}

bool InetAddress::parseAddress(const std::string &address, in_addr &result) {
  if (address == "localhost") {
    result.s_addr = htonl(INADDR_LOOPBACK);
    return true;
  }
  return inet_pton(AF_INET, address.c_str(), &result) > 0;
}

bool InetAddress::parsePort(const std::string &portStr, in_port_t &result) {
  try {
    int port = std::stoi(portStr);
    if (port <= 0 || port > 65535) {
      return false;
    }
    result = static_cast<in_port_t>(port);
    return true;
  } catch (...) {
    return false;
  }
}

std::string InetAddress::handleAddress(sockaddr_in *conf, const std::string &value) {
  if (value == "*") {
    return "";
  }

  int result = inet_pton(AF_INET, value.c_str(), &(conf->sin_addr));

  if (result == 0) {
    std::string message = "Invalid IP Address format. IP Address: " + value;
    return message;
  }

  if (result < 0) {
    std::string message = "Unknown error! message: " + std::string(std::strerror(errno));
    return message;
  }

  return "";
}

std::string InetAddress::handleNoColon(sockaddr_in *conf, const std::string &value) {
  if (value == "localhost") {
    conf->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return "";
  }

  if (handlePort(conf, value) == "") {
    return "";
  }

  if (handleAddress(conf, value) == "") {
    return "";
  }

  std::string message = "Invalid listen Argument! Argument: " + value;
  return message;
}

InetAddress::InetAddress() {
  std::lock_guard<std::mutex> lock(configMutex_);
  if (!isInitialized_) {
    throw std::runtime_error("InetAddress not initialized");
  }
  addr_ = globalConfig_;
}

InetAddress::InetAddress(in_port_t port, bool loopbackOnly) {
  std::lock_guard<std::mutex> lock(configMutex_);

  if (!isInitialized_) {
    throw std::runtime_error("InetAddress not initialized");
  }

  addr_          = globalConfig_;
  addr_.sin_port = htons(port);

  if (loopbackOnly) {
    addr_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }
}

InetAddress::InetAddress(const std::string &address, in_port_t port) {
  std::lock_guard<std::mutex> lock(configMutex_);

  if (!isInitialized_) {
    throw std::runtime_error("InetAddress not initialized");
  }

  addr_          = globalConfig_;
  addr_.sin_port = htons(port);

  if (::inet_pton(AF_INET, address.c_str(), &addr_.sin_addr) <= 0) {
    throw std::invalid_argument("Invalid IP address");
  }
}

InetAddress::InetAddress(const struct sockaddr_in &addr) {
  addr_ = addr;
}

std::string InetAddress::getIp() const {
  const static int bufSize = 64;
  std::array<char, bufSize> buf;
  ::inet_ntop(AF_INET, &addr_.sin_addr, buf.data(), sizeof(buf));
  return buf.data();
}

in_port_t InetAddress::getPort() const {
  return ::ntohs(addr_.sin_port);
}

std::string InetAddress::getIpPort() const {
  return getIp() + ":" + std::to_string(getPort());
}

void InetAddress::setSockAddr(const struct sockaddr_in &addr) {
  std::lock_guard<std::mutex> lock(configMutex_);
  addr_ = addr;
}

bool InetAddress::resolveHostname(const std::string &hostname, InetAddress *result) {
  addrinfo hints    = {};
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo *res = nullptr;
  if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
    return false;
  }

  if (result != nullptr) {
    sockaddr_in addr;
    memcpy(&addr, res->ai_addr, sizeof(sockaddr_in));
    addr.sin_port = 0;
    result->setSockAddr(addr);
  }

  freeaddrinfo(res);
  return true;
}
} // namespace server
