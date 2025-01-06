#include "include/certificate_manager.h"

#include "include/acme_client.h"
#include "include/key_pair_manager.h"
#include "include/log.h"
#include "include/types.h"

#include <openssl/pem.h>

namespace server {

CertificateManager::CertificateManager(const ServerConfig &config)
    : config_(config) {}

int CertificateManager::verifyCertificate(
    const std::string &certPath,
    const std::string &keyPath,
    int renewDay
) {
  auto store    = UniqueStore(X509_STORE_new());
  auto storeCtx = UniqueStoreCtx(X509_STORE_CTX_new());

  if (!store || !storeCtx) {
    return CERTIFICATE_INVALID;
  }

  auto cert = loadCertificate(certPath);
  if (X509_STORE_CTX_init(storeCtx.get(), store.get(), cert.get(), nullptr) != 1) {
    return CERTIFICATE_INVALID;
  }

  if (X509_verify_cert(storeCtx.get()) != 1) {
    return CERTIFICATE_INVALID;
  }

  auto key    = KeyPairManager::loadPrivateKey(keyPath);
  auto pubKey = UniqueEvpKey(X509_get_pubkey(cert.get()), EVP_PKEY_free);
  if (!key || !pubKey || !KeyPairManager::verifyKeyPair(pubKey.get(), key.get())) {
    return KEY_PAIR_INVALID;
  }

  const ASN1_TIME *notAfter = X509_get0_notAfter(cert.get());
  if (notAfter == nullptr) {
    return CERTIFICATE_INVALID;
  }

  int days;
  int seconds;
  if (ASN1_TIME_diff(&days, &seconds, nullptr, notAfter) == 0) {
    return CERTIFICATE_INVALID;
  }
  if (days < 0) {
    return CERTIFICATE_INVALID;
  }

  if (days <= renewDay) {
    return CERTIFICATE_NEED_UPDATE;
  }

  return CERTIFICATE_VALID;
}

void CertificateManager::ensureValidCertificate() const {
  if (!std::filesystem::exists(config_.sslCertFile)) {
    LOG_DEBUG("Certificate file not found");
    requestNewCertificate();
    return;
  }
  LOG_DEBUG("Certificate file found");

  auto cert = loadCertificate(config_.sslCertFile);

  if (!verifyCertificate(config_.sslCertFile, config_.sslCertKeyFile)) {
    LOG_DEBUG("Certificate verification failed");
  }

  if (!verifyCertificate(config_.sslCertFile, config_.sslCertKeyFile)
      || !verifyCertificateExpiration(cert.get(), config_.sslRenewDays)) {
    if (!config_.sslEnableAutoGen) {
      throw std::runtime_error("Invalid or expired certificate and auto-generation is disabled");
    }
    requestNewCertificate();
  }
}

bool CertificateManager::verifyCertificate(std::string_view certPath, std::string_view keyPath) {
  auto store    = UniqueStore(X509_STORE_new());
  auto storeCtx = UniqueStoreCtx(X509_STORE_CTX_new());
  if (!store || !storeCtx) {
    return false;
  }

  auto cert = loadCertificate(certPath);
  if (X509_STORE_CTX_init(storeCtx.get(), store.get(), cert.get(), nullptr) != 1) {
    return false;
  }

  if (X509_verify_cert(storeCtx.get()) != 1) {
    return false;
  }

  auto key    = KeyPairManager::loadPrivateKey(keyPath);
  auto pubKey = UniqueEvpKey(X509_get_pubkey(cert.get()), EVP_PKEY_free);
  return key && pubKey && KeyPairManager::verifyKeyPair(pubKey.get(), key.get());
}

bool CertificateManager::verifyCertificateExpiration(
    const X509 *certificate,
    uint16_t renewBeforeDays
) {
  if (certificate == nullptr) {
    return false;
  }

  const ASN1_TIME *notBefore = X509_get0_notBefore(certificate);
  const ASN1_TIME *notAfter  = X509_get0_notAfter(certificate);
  if ((notBefore == nullptr) || (notAfter == nullptr)) {
    return false;
  }

  int days    = 0;
  int seconds = 0;
  if (ASN1_TIME_diff(&days, &seconds, nullptr, notAfter) == 0) {
    return false;
  }

  return days > static_cast<int>(renewBeforeDays);
}

UniqueX509 CertificateManager::loadCertificate(std::string_view path) {
  auto bio = createBioFile(std::string(path), "r");

  X509 *cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    throw std::runtime_error("Failed to read certificate: " + std::string(path));
  }

  return { cert, X509_free };
}

void CertificateManager::requestNewCertificate() const {
  AcmeClient acmeClient(config_);

  acmeClient.createCertificate();
}

} // namespace server
