#include "include/config_defaults.h"
#include "include/log.h"
#include "include/ssl_manager.h"

#include <filesystem>
#include <gtest/gtest.h>

namespace server {

class SSLManagerTest : public ::testing::Test {
protected:
  void SetUp() override {
    cleanupTestFiles();
    setupTestConfig();
  }

  void TearDown() override { cleanupTestFiles(); }

  static void cleanupTestFiles() {
    std::filesystem::path dir = std::string(kProjectRoot) + "server/auto/ssl";
    if (!std::filesystem::exists(dir)) {
      return;
    }

    for (const auto &file : std::filesystem::directory_iterator(dir)) {
      std::filesystem::remove_all(file.path());
    }
  }

  void setupTestConfig() {
    config_.address          = "test.com";
    config_.sslApiUrl        = "https://acme-staging-v02.api.letsencrypt.org/directory"; // staging
    config_.sslEmail         = "ddyu.whisper.personal@gmail.com";
    config_.sslKeyType       = "rsaEncryption";
    config_.sslKeyParam      = 2048;
    config_.sslRenewDays     = 30;
    config_.sslEnableAutoGen = true;

    setupTestDirectories();
  }

  static void setupTestDirectories() {
    std::filesystem::path sslDir = std::string(kProjectRoot) + "server/auto/ssl";
    std::filesystem::create_directories(sslDir);

    std::filesystem::permissions(
        sslDir,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
            | std::filesystem::perms::owner_exec,
        std::filesystem::perm_options::replace
    );
  }

  ServerConfig config_;
};

TEST_F(SSLManagerTest, TestInitialConfiguration) {
  auto &manager = SSLManager::getInstance();
  EXPECT_NO_THROW(manager.addServer(config_));
  EXPECT_EQ(manager.getCertificatePath(config_.address), config_.sslCertFile);
  EXPECT_EQ(manager.getPrivateKeyPath(config_.address), config_.sslPrivateKeyFile);
}

TEST_F(SSLManagerTest, TestKeyPairGeneration) {
  try {
    auto &manager = SSLManager::getInstance();
    LOG_INFO("Starting key pair generation test");

    manager.addServer(config_);
    LOG_INFO("Server configuration added");

    EXPECT_TRUE(std::filesystem::exists(config_.sslPrivateKeyFile))
        << "Private key file does not exist: " << config_.sslPrivateKeyFile;
    EXPECT_TRUE(std::filesystem::exists(config_.sslPublicKeyFile))
        << "Public key file does not exist: " << config_.sslPublicKeyFile;

    auto privateKeyPerms = std::filesystem::status(config_.sslPrivateKeyFile).permissions();
    EXPECT_TRUE(
        (privateKeyPerms & std::filesystem::perms::group_all) == std::filesystem::perms::none
    ) << "Private key has incorrect group permissions";
    EXPECT_TRUE(
        (privateKeyPerms & std::filesystem::perms::others_all) == std::filesystem::perms::none
    ) << "Private key has incorrect other permissions";

    LOG_INFO("Key pair generation test completed successfully");
  } catch (const std::exception &e) {
    FAIL() << "Exception occurred: " << e.what();
  }
}

TEST_F(SSLManagerTest, TestACMERegistration) {
  auto &manager = SSLManager::getInstance();
  EXPECT_NO_THROW({
    manager.addServer(config_);
    EXPECT_TRUE(std::filesystem::exists(config_.sslAccountUrlFile));
  });
}

TEST_F(SSLManagerTest, TestMultiDomainSupport) {
  auto &manager = SSLManager::getInstance();

  ServerConfig config2 = config_;
  config2.address      = "test2.xiuzhe.xyz";

  EXPECT_NO_THROW({
    manager.addServer(config_);
    manager.addServer(config2);

    EXPECT_EQ(manager.getCertificatePath(config_.address), config_.sslCertFile);
    EXPECT_EQ(manager.getCertificatePath(config2.address), config2.sslCertFile);
  });
}

TEST_F(SSLManagerTest, TestErrorHandling) {
  auto &manager = SSLManager::getInstance();

  ServerConfig invalidConfig = config_;
  invalidConfig.sslApiUrl    = "https://invalid.acme.server/directory";
  EXPECT_THROW(manager.addServer(invalidConfig), std::runtime_error);

  invalidConfig          = config_;
  invalidConfig.sslEmail = "";
  EXPECT_THROW(manager.addServer(invalidConfig), std::runtime_error);

  invalidConfig             = config_;
  invalidConfig.sslKeyParam = -1;
  EXPECT_THROW(manager.addServer(invalidConfig), std::runtime_error);
}

} // namespace server
