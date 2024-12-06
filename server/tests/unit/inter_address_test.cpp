#include "include/inet_address.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>

namespace server {
namespace {

class InetAddressTest : public ::testing::Test {
protected:
  const in_port_t kTestPort = 8080;
  const std::string kTestIp = "192.168.1.1";
  const std::string kLoopbackIp = "127.0.0.1";
};

TEST_F(InetAddressTest, DefaultConstructorBindsToAnyAddress) {
  InetAddress addr(kTestPort);

  EXPECT_EQ(addr.getIp(), "0.0.0.0");
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InetAddressTest, LoopbackOnlyBindsToLocalhost) {
  InetAddress addr(kTestPort, true);

  EXPECT_EQ(addr.getIp(), kLoopbackIp);
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InetAddressTest, ConstructWithValidIpAndPort) {
  InetAddress addr(kTestIp, kTestPort);

  EXPECT_EQ(addr.getIp(), kTestIp);
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InetAddressTest, ConstructWithInvalidIpThrowsException) {
  EXPECT_THROW(InetAddress("invalid.ip", kTestPort), std::invalid_argument);
}

TEST_F(InetAddressTest, GetIpPortReturnsFormattedString) {
  InetAddress addr(kTestIp, kTestPort);

  std::string expected = kTestIp + ":" + std::to_string(kTestPort);
  EXPECT_EQ(addr.getIpPort(), expected);
}

TEST_F(InetAddressTest, ConstructFromSockAddrRetainsValues) {
  sockaddr_in sock_addr = {};
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(kTestPort);
  inet_pton(AF_INET, kTestIp.c_str(), &sock_addr.sin_addr);

  InetAddress addr(sock_addr);

  EXPECT_EQ(addr.getIp(), kTestIp);
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InetAddressTest, ResolveValidHostnameSucceeds) {
  InetAddress result(kTestPort);

  EXPECT_TRUE(InetAddress::resolveHostname("localhost", &result));
  EXPECT_EQ(result.getIp(), kLoopbackIp);
}

TEST_F(InetAddressTest, ResolveInvalidHostnameFails) {
  InetAddress result(kTestPort);

  EXPECT_FALSE(InetAddress::resolveHostname("invalid.hostname.local", &result));
}

TEST_F(InetAddressTest, PortZeroIsValid) {
  InetAddress addr(0);

  EXPECT_EQ(addr.getPort(), 0);
}

TEST_F(InetAddressTest, MaxPortIsValid) {
  const in_port_t kMaxPort = 65535;
  InetAddress addr(kMaxPort);

  EXPECT_EQ(addr.getPort(), kMaxPort);
}

} // namespace
} // namespace server
