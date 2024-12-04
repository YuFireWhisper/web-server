#include "include/inter_address.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>

namespace server {
namespace {

class InterAddressTest : public ::testing::Test {
protected:
  const in_port_t kTestPort = 8080;
  const std::string kTestIp = "192.168.1.1";
  const std::string kLoopbackIp = "127.0.0.1";
};

TEST_F(InterAddressTest, DefaultConstructorBindsToAnyAddress) {
  InterAddress addr(kTestPort);

  EXPECT_EQ(addr.getIp(), "0.0.0.0");
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InterAddressTest, LoopbackOnlyBindsToLocalhost) {
  InterAddress addr(kTestPort, true);

  EXPECT_EQ(addr.getIp(), kLoopbackIp);
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InterAddressTest, ConstructWithValidIpAndPort) {
  InterAddress addr(kTestIp, kTestPort);

  EXPECT_EQ(addr.getIp(), kTestIp);
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InterAddressTest, ConstructWithInvalidIpThrowsException) {
  EXPECT_THROW(InterAddress("invalid.ip", kTestPort), std::invalid_argument);
}

TEST_F(InterAddressTest, GetIpPortReturnsFormattedString) {
  InterAddress addr(kTestIp, kTestPort);

  std::string expected = kTestIp + ":" + std::to_string(kTestPort);
  EXPECT_EQ(addr.getIpPort(), expected);
}

TEST_F(InterAddressTest, ConstructFromSockAddrRetainsValues) {
  sockaddr_in sock_addr = {};
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(kTestPort);
  inet_pton(AF_INET, kTestIp.c_str(), &sock_addr.sin_addr);

  InterAddress addr(sock_addr);

  EXPECT_EQ(addr.getIp(), kTestIp);
  EXPECT_EQ(addr.getPort(), kTestPort);
}

TEST_F(InterAddressTest, ResolveValidHostnameSucceeds) {
  InterAddress result(kTestPort);

  EXPECT_TRUE(InterAddress::resolveHostname("localhost", &result));
  EXPECT_EQ(result.getIp(), kLoopbackIp);
}

TEST_F(InterAddressTest, ResolveInvalidHostnameFails) {
  InterAddress result(kTestPort);

  EXPECT_FALSE(InterAddress::resolveHostname("invalid.hostname.local", &result));
}

TEST_F(InterAddressTest, PortZeroIsValid) {
  InterAddress addr(0);

  EXPECT_EQ(addr.getPort(), 0);
}

TEST_F(InterAddressTest, MaxPortIsValid) {
  const in_port_t kMaxPort = 65535;
  InterAddress addr(kMaxPort);

  EXPECT_EQ(addr.getPort(), kMaxPort);
}

} // namespace
} // namespace server
