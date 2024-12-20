#include "include/inet_address.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <stdexcept>

namespace server {
namespace {

class InetAddressTest : public ::testing::Test {
protected:
  const sa_family_t kAddressFamily = AF_INET;
  const in_port_t kPort            = 8080;
  const in_port_t kMaxPort         = 65535;
  const std::string kIpv4Address   = "192.168.1.1";
  const std::string kLoopbackIp    = "127.0.0.1";
  const std::string kAnyAddress    = "0.0.0.0";
};

TEST_F(InetAddressTest, CreateWithValidIpAndPort) {
  InetAddress addr(kAddressFamily, kIpv4Address, kPort);

  EXPECT_EQ(addr.getIp(), kIpv4Address);
  EXPECT_EQ(addr.getPort(), kPort);
  EXPECT_EQ(addr.getAddressFamily(), kAddressFamily);
}

TEST_F(InetAddressTest, CreateWithInvalidIpThrows) {
  EXPECT_THROW(InetAddress(kAddressFamily, "invalid.ip", kPort), std::invalid_argument);
}

TEST_F(InetAddressTest, CreateWithInvalidPortThrows) {
  const in_port_t invalidPort = 0;
  EXPECT_THROW(InetAddress(kAddressFamily, kIpv4Address, invalidPort), std::invalid_argument);
  EXPECT_THROW(InetAddress(kAddressFamily, kIpv4Address, 0), std::invalid_argument);
}

TEST_F(InetAddressTest, CreateWithAnyAddress) {
  InetAddress addr(kAddressFamily, "*", kPort);

  EXPECT_EQ(addr.getIp(), kAnyAddress);
  EXPECT_EQ(addr.getPort(), kPort);
}

TEST_F(InetAddressTest, CreateWithEmptyAddress) {
  InetAddress addr(kAddressFamily, "", kPort);

  EXPECT_EQ(addr.getIp(), kAnyAddress);
  EXPECT_EQ(addr.getPort(), kPort);
}

TEST_F(InetAddressTest, CreateWithLocalhost) {
  InetAddress addr(kAddressFamily, "localhost", kPort);

  EXPECT_EQ(addr.getIp(), kLoopbackIp);
  EXPECT_EQ(addr.getPort(), kPort);
}

TEST_F(InetAddressTest, CreateWithLoopbackFlag) {
  InetAddress addr(kAddressFamily, kPort, true);

  EXPECT_EQ(addr.getIp(), kLoopbackIp);
  EXPECT_EQ(addr.getPort(), kPort);
}

TEST_F(InetAddressTest, CreateWithAnyAddressFlag) {
  InetAddress addr(kAddressFamily, kPort, false);

  EXPECT_EQ(addr.getIp(), kAnyAddress);
  EXPECT_EQ(addr.getPort(), kPort);
}

TEST_F(InetAddressTest, GetIpPortFormat) {
  InetAddress addr(kAddressFamily, kIpv4Address, kPort);

  std::string expected = kIpv4Address + ":" + std::to_string(kPort);
  EXPECT_EQ(addr.getIpPort(), expected);
}

TEST_F(InetAddressTest, CreateFromSockAddr) {
  sockaddr_in sock_addr{};
  sock_addr.sin_family = kAddressFamily;
  sock_addr.sin_port   = htons(kPort);
  inet_pton(kAddressFamily, kIpv4Address.c_str(), &sock_addr.sin_addr);

  InetAddress addr(sock_addr);

  EXPECT_EQ(addr.getIp(), kIpv4Address);
  EXPECT_EQ(addr.getPort(), kPort);
  EXPECT_EQ(addr.getAddressFamily(), kAddressFamily);
}

TEST_F(InetAddressTest, ResolveLocalhostSucceeds) {
  InetAddress result(kAddressFamily, kPort);

  EXPECT_TRUE(InetAddress::resolveHostname("localhost", &result));
  EXPECT_EQ(result.getIp(), kLoopbackIp);
}

TEST_F(InetAddressTest, ResolveInvalidHostnameFails) {
  InetAddress result(kAddressFamily, kPort);

  EXPECT_FALSE(InetAddress::resolveHostname("invalid.hostname.test", &result));
}

TEST_F(InetAddressTest, GetSockAddrAndLen) {
  InetAddress addr(kAddressFamily, kIpv4Address, kPort);

  EXPECT_NE(addr.getSockAddr(), nullptr);
  EXPECT_EQ(addr.getSockLen(), sizeof(sockaddr_in));
}

TEST_F(InetAddressTest, MaxValidPort) {
  InetAddress addr(kAddressFamily, kIpv4Address, kMaxPort);

  EXPECT_EQ(addr.getPort(), kMaxPort);
}

} // namespace
} // namespace server
