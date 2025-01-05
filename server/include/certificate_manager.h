#include "include/config_defaults.h"

namespace server {

class CertificateManager {
public:
  explicit CertificateManager(const ServerConfig &config);

  void ensureValidCertificate() const;
  static bool verifyCertificate(std::string_view certPath, std::string_view keyPath);
  static bool verifyCertificateExpiration(const X509 *certificate, uint16_t renewBeforeDays);
  static std::unique_ptr<X509, void (*)(X509 *)> loadCertificate(std::string_view path);

private:
  void requestNewCertificate() const;
  const ServerConfig &config_;
};

} // namespace server
