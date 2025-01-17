#pragma once

#include "include/types.h"

namespace server {

constexpr int CERTIFICATE_INVALID     = -1;
constexpr int CERTIFICATE_NEED_UPDATE = 0;
constexpr int CERTIFICATE_VALID       = 1;

struct CertChain {
  UniqueX509 leaf;
  UniqueStack intermediates;
};

struct CertInfo {
  std::string fileName      = "UNKNOWN";
  std::string domain        = "UNKNOWN";
  std::string issuer        = "UNKNOWN";
  std::string validityStart = "UNKNOWN";
  std::string validityEnd   = "UNKNOWN";
};

class CertificateManager {
public:
  static int
  verifyCertificate(const std::string &certPath, const std::string &keyPath, int renewDay);

  static UniqueX509 loadCertificate(std::string_view path);
  static CertChain loadCertificateChain(const std::string &path);

  static CertInfo getCertInfo(const std::string &path);
};

} // namespace server
