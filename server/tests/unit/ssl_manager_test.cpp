#include "include/config_defaults.h"
#include "include/ssl_manager.h"

#include <filesystem>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

namespace server::test {

class SSLManagerTest : public ::testing::Test {
protected:
  void SetUp() override {
    cleanupTestFiles();
    setupTestConfig();
  }

  void TearDown() override { cleanupTestFiles(); }

  void setupTestConfig() {
    config.address          = "127.0.0.1";
    config.serverName       = "test.domain.com";
    config.sslEnable        = true;
    config.sslEnableAutoGen = true;
    config.sslKeyType       = "ED25519";
    config.sslKeyParam      = 0;
    config.sslApiUrl        = "https://acme-staging-v02.api.letsencrypt.org/directory";
    config.sslEmail         = "test@domain.com";
    config.sslRenewDays     = 30;

    const std::string testDir = std::string(kProjectRoot) + "server/auto/ssl/";
    std::filesystem::create_directories(testDir);

    config.sslCertFile         = testDir + config.address + "_.crt";
    config.sslPublicKeyFile    = testDir + config.address + "_public.key";
    config.sslPrivateKeyFile   = testDir + config.address + "_private.key";
    config.sslAccountUrlFile   = testDir + config.address + "_account.url";
    config.sslLocationUrlFile  = testDir + config.address + "_location.url";
    config.sslFinalizeUrlFile  = testDir + config.address + "_finalize.url";
    config.sslChallengeUrlFile = testDir + config.address + "_challenge.url";
  }

  static void cleanupTestFiles() {
    const std::string testDir = std::string(kProjectRoot) + "server/auto/ssl/";
    if (std::filesystem::exists(testDir)) {
      std::filesystem::remove_all(testDir);
    }
  }

  ServerConfig config;
};

TEST_F(SSLManagerTest, GetInstanceReturnsSameInstance) {
  auto &instance1 = SSLManager::getInstance();
  auto &instance2 = SSLManager::getInstance();
  EXPECT_EQ(&instance1, &instance2);
}

TEST_F(SSLManagerTest, AddServerWithValidConfigSucceeds) {
  auto &manager = SSLManager::getInstance();
  EXPECT_NO_THROW(manager.addServer(config));
}

TEST_F(SSLManagerTest, AddServerWithDuplicateAddressFails) {
  auto &manager = SSLManager::getInstance();
  manager.addServer(config);

  ServerConfig duplicateConfig = config;
  EXPECT_THROW(manager.addServer(duplicateConfig), std::runtime_error);
}

TEST_F(SSLManagerTest, GetCertificatePathReturnsCorrectPath) {
  auto &manager = SSLManager::getInstance();
  manager.addServer(config);

  EXPECT_EQ(manager.getCertificatePath(config.address), config.sslCertFile);
}

TEST_F(SSLManagerTest, GetPrivateKeyPathReturnsCorrectPath) {
  auto &manager = SSLManager::getInstance();
  manager.addServer(config);

  EXPECT_EQ(manager.getPrivateKeyPath(config.address), config.sslPrivateKeyFile);
}

TEST_F(SSLManagerTest, GetCertificatePathWithInvalidAddressFails) {
  auto &manager = SSLManager::getInstance();
  manager.addServer(config);

  EXPECT_THROW(manager.getCertificatePath("invalid.address"), std::runtime_error);
}

TEST_F(SSLManagerTest, GetPrivateKeyPathWithInvalidAddressFails) {
  auto &manager = SSLManager::getInstance();
  manager.addServer(config);

  EXPECT_THROW(manager.getPrivateKeyPath("invalid.address"), std::runtime_error);
}

TEST_F(SSLManagerTest, ValidateAndUpdateChallengeWithNoActiveConfigFails) {
  auto &manager = SSLManager::getInstance();
  EXPECT_THROW(manager.validateAndUpdateChallenge(), std::runtime_error);
}

TEST_F(SSLManagerTest, AddServerWithDisabledAutoGenAndMissingCertificateFails) {
  config.sslEnableAutoGen = false;
  auto &manager           = SSLManager::getInstance();
  EXPECT_THROW(manager.addServer(config), std::runtime_error);
}

TEST_F(SSLManagerTest, AddServerWithInvalidKeyTypeFails) {
  config.sslKeyType = "INVALID_KEY_TYPE";
  auto &manager     = SSLManager::getInstance();
  EXPECT_THROW(manager.addServer(config), std::runtime_error);
}

TEST_F(SSLManagerTest, AddServerWithEmptyEmailFails) {
  config.sslEmail = "";
  auto &manager   = SSLManager::getInstance();
  EXPECT_THROW(manager.addServer(config), std::runtime_error);
}

TEST_F(SSLManagerTest, AddServerWithInvalidApiUrlFails) {
  config.sslApiUrl = "invalid_url";
  auto &manager    = SSLManager::getInstance();
  EXPECT_THROW(manager.addServer(config), std::runtime_error);
}

TEST_F(SSLManagerTest, AddServerCreatesRequiredDirectories) {
  auto &manager = SSLManager::getInstance();
  manager.addServer(config);

  const std::string sslDir = std::string(kProjectRoot) + "server/auto/ssl/";
  EXPECT_TRUE(std::filesystem::exists(sslDir));
  EXPECT_TRUE(std::filesystem::is_directory(sslDir));
}

TEST_F(SSLManagerTest, AddServerGeneratesKeyPair) {
  auto &manager = SSLManager::getInstance();
  manager.addServer(config);

  EXPECT_TRUE(std::filesystem::exists(config.sslPublicKeyFile));
  EXPECT_TRUE(std::filesystem::exists(config.sslPrivateKeyFile));
}

TEST_F(SSLManagerTest, AddServerWithRSAKeyTypeSucceeds) {
  config.sslKeyType  = "RSA";
  config.sslKeyParam = 2048;
  auto &manager      = SSLManager::getInstance();
  EXPECT_NO_THROW(manager.addServer(config));
}

class SSLManagerIntegrationTest : public SSLManagerTest {
protected:
  void SetUp() override {
    SSLManagerTest::SetUp();
    config.sslApiUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";
  }
};

TEST_F(SSLManagerIntegrationTest, FullCertificateLifecycleTest) {
  auto &manager = SSLManager::getInstance();
  ASSERT_NO_THROW(manager.addServer(config));

  EXPECT_TRUE(std::filesystem::exists(config.sslPublicKeyFile));
  EXPECT_TRUE(std::filesystem::exists(config.sslPrivateKeyFile));

  std::this_thread::sleep_for(std::chrono::seconds(2));

  bool challengeResult = manager.validateAndUpdateChallenge();
  EXPECT_TRUE(challengeResult);

  if (challengeResult) {
    EXPECT_TRUE(std::filesystem::exists(config.sslCertFile));
  }
}

} // namespace server::test
