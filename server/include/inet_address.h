#include <netinet/in.h>
#include <string>
#include <unistd.h>

namespace server {

class InetAddress {
public:
  explicit InetAddress(in_port_t port = 0, bool loopbackOnly = false);
  InetAddress(const std::string &ip, in_port_t port);
  explicit InetAddress(const struct sockaddr_in &addr);

  std::string getIp() const;
  std::string getIpPort() const;
  in_port_t getPort() const;

  const sockaddr *getSockAddr() const { return reinterpret_cast<const sockaddr *>(&addr_); }
  const socklen_t getSockLen() const { return sizeof(addr_); }
  void setSockAddr(const struct sockaddr_in &addr) { addr_ = addr; }

  static bool resolveHostname(const std::string &hostname, InetAddress *result);

private:
  sockaddr_in addr_;

  void initializeAddr(in_port_t port);
};

} // namespace server