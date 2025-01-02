#include "include/config_defaults.h"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/types.h>
namespace server {

class AcmeCertManager {
public:
  AcmeCertManager(ServerConfig config);
  ~AcmeCertManager();

  void createAccount();

  static EVP_PKEY *generatePkey(const char *type, int param);

private:
  static int stringToNid(const char *s);
  void getCaUrlsAndStore();
  std::string getNonce();
  std::string createSignature(const std::string& protectedB64, const std::string& payloadB64);

  static CURL *initializeCurl(std::string &response);
  static size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *userp);
  static void get(const std::string &url, CURL *curl, std::string &response);
  static void head(const std::string &url, CURL *curl, std::string &response);
  static std::string getHeader(const std::string &response, const std::string &header);

  static std::string encodeBase64(const std::string &str);

  ServerConfig config_;
  EVP_PKEY *pkey_;
  CURL *curl_;
  std::string response_;

  std::string newAccountUrl_;
  std::string newOrderUrl_;
  std::string nonceUrl_;
  std::string keyChangeUrl_;
  std::string revokeCertUrl_;

  std::string accountUrl_;
};
} // namespace server
