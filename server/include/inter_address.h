#include <netinet/in.h>
#include <string>
#include <unistd.h>

namespace server {

class InterAddress {
public:
  explicit InterAddress(in_port_t port = 0, bool loopbackOnly = false);
  InterAddress(const std::string &ip, in_port_t port);
  explicit InterAddress(const struct sockaddr_in &addr);

  std::string getIp() const;
  std::string getIpPort() const;
  in_port_t getPort() const;

  const sockaddr_in *getSockAddr() const { return &addr_; }
  const socklen_t getSockLen() const { return sizeof(addr_); } 
  void setSockAddr(const struct sockaddr_in &addr) { addr_ = addr; }

  static bool resolveHostname(const std::string &hostname, InterAddress *result);

private:
  sockaddr_in addr_;

  void initializeAddr(in_port_t port);
};

} // namespace server
