#include "include/certificate_manager.h"

#include "include/file_system.h"
#include "include/key_pair_manager.h"
#include "include/log.h"
#include "include/types.h"

#include <openssl/pem.h>

namespace server {
int CertificateManager::verifyCertificate(
    const std::string &certPath,
    const std::string &keyPath,
    int renewDay
) {
  if (!FileSystem::isAllExist(certPath, keyPath)) {
    LOG_DEBUG("Certificate or key file not found");
    return CERTIFICATE_INVALID;
  }
  auto store    = UniqueStore(X509_STORE_new());
  auto storeCtx = UniqueStoreCtx(X509_STORE_CTX_new());

  if (!store || !storeCtx) {
    LOG_DEBUG("Failed to create store or store context");
    return CERTIFICATE_INVALID;
  }

  if (X509_STORE_set_default_paths(store.get()) != 1) {
    LOG_DEBUG("Failed to load system trust store");
    return CERTIFICATE_INVALID;
  }

  auto certChain = loadCertificateChain(certPath);

  if (X509_STORE_CTX_init(
          storeCtx.get(),
          store.get(),
          certChain.leaf.get(),
          certChain.intermediates.get()
      )
      != 1) {
    LOG_DEBUG("Failed to initialize store context");
    return CERTIFICATE_INVALID;
  }

  if (X509_verify_cert(storeCtx.get()) != 1) {
    int err            = X509_STORE_CTX_get_error(storeCtx.get());
    const char *errStr = X509_verify_cert_error_string(err);
    LOG_DEBUG("Failed to verify certificate: " + std::string(errStr));
    return CERTIFICATE_INVALID;
  }

  auto key    = KeyPairManager::loadPrivateKey(keyPath);
  auto pubKey = UniqueEvpKey(X509_get_pubkey(certChain.leaf.get()), EVP_PKEY_free);
  if (!key || !pubKey || (KeyPairManager::verifyKeyPair(pubKey.get(), key.get()) == 0)) {
    return KEY_PAIR_INVALID;
  }

  const ASN1_TIME *notAfter = X509_get0_notAfter(certChain.leaf.get());
  if (notAfter == nullptr) {
    LOG_DEBUG("Certificate expiration date not found");
    return CERTIFICATE_INVALID;
  }

  int days;
  int seconds;
  if (ASN1_TIME_diff(&days, &seconds, nullptr, notAfter) == 0) {
    LOG_DEBUG("Failed to calculate certificate expiration date");
    return CERTIFICATE_INVALID;
  }
  if (days < 0) {
    LOG_DEBUG("Certificate expired");
    return CERTIFICATE_INVALID;
  }

  if (days <= renewDay) {
    return CERTIFICATE_NEED_UPDATE;
  }

  return CERTIFICATE_VALID;
}

UniqueX509 CertificateManager::loadCertificate(std::string_view path) {
  auto bio = createBioFile(std::string(path), "r");

  X509 *cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    throw std::runtime_error("Failed to read certificate: " + std::string(path));
  }

  return { cert, X509_free };
}

CertChain CertificateManager::loadCertificateChain(const std::string &path) {
  auto bio = createBioFile(path, "r");

  X509 *cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (cert == nullptr) {
    throw std::runtime_error("Failed to read certificate: " + path);
  }

  auto intermediates = UniqueStack(sk_X509_new_null());
  if (intermediates == nullptr) {
    throw std::runtime_error("Failed to create certificate stack");
  }

  while (true) {
    X509 *intermediate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (intermediate == nullptr) {
      break;
    }

    if (sk_X509_push(intermediates.get(), intermediate) == 0) {
      throw std::runtime_error("Failed to push certificate to stack");
    }
  }

  return { UniqueX509(cert, X509_free), std::move(intermediates) };
}

CertInfo CertificateManager::getCertInfo(const std::string &path) {
  auto cert = loadCertificate(path);
  CertInfo info;
  if (!cert) {
    return info;
  }

  info.fileName = FileSystem::getFileName(path);

  if (X509_NAME *subject = X509_get_subject_name(cert.get())) {
    char commonName[256];
    if (X509_NAME_get_text_by_NID(subject, NID_commonName, commonName, sizeof(commonName)) > 0) {
      info.domain = commonName;
    }
  }

  if (X509_NAME *issuer = X509_get_issuer_name(cert.get())) {
    char buffer[256];
    int nid_priority[] = { NID_organizationName, NID_commonName, NID_countryName };

    for (int nid : nid_priority) {
      if (X509_NAME_get_text_by_NID(issuer, nid, buffer, sizeof(buffer)) > 0) {
        info.issuer = buffer;
        break;
      }
    }
  }

  auto formatTime = [](const ASN1_TIME *time) -> std::string {
    if (!time) {
      return "UNKNOWN";
    }

    struct tm timeinfo;
    if (ASN1_TIME_to_tm(time, &timeinfo) != 1) {
      return "UNKNOWN";
    }

    char buffer[37]; // YYYY/MM/DD + null terminator
    snprintf(
        buffer,
        sizeof(buffer),
        "%04d/%02d/%02d",
        timeinfo.tm_year + 1900,
        timeinfo.tm_mon + 1,
        timeinfo.tm_mday
    );

    return { buffer };
  };

  if (const ASN1_TIME *not_before = X509_get_notBefore(cert.get())) {
    info.validityStart = formatTime(not_before);
  }

  if (const ASN1_TIME *not_after = X509_get_notAfter(cert.get())) {
    info.validityEnd = formatTime(not_after);
  }

  return info;
}

} // namespace server
