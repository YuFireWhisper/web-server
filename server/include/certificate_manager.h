#include "include/config_defaults.h"

namespace server {

constexpr int KEY_PAIR_INVALID        = -2;
constexpr int CERTIFICATE_INVALID     = -1;
constexpr int CERTIFICATE_NEED_UPDATE = 0;
constexpr int CERTIFICATE_VALID       = 1;

struct CertChain {
    UniqueX509 leaf;
    UniqueStack intermediates;
};

class CertificateManager {
public:
  [[deprecated]] explicit CertificateManager(const ServerConfig &config);

  static int
  verifyCertificate(const std::string &certPath, const std::string &keyPath, int renewDay);

  static UniqueX509 loadCertificate(std::string_view path);
  static CertChain loadCertificateChain(const std::string& path);

  [[deprecated]] void ensureValidCertificate() const;
  [[deprecated]] static bool verifyCertificate(std::string_view certPath, std::string_view keyPath);
  [[deprecated]] static bool
  verifyCertificateExpiration(const X509 *certificate, uint16_t renewBeforeDays);

private:
  [[deprecated]] void requestNewCertificate() const;
  const ServerConfig &config_;
};

} // namespace server
