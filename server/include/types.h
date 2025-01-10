#pragma once

#include <cstdint>
#include <curl/curl.h>
#include <functional>
#include <memory>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <poll.h>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sys/epoll.h>

namespace server {
class TimeStamp;
class Timer;
class Channel;
class Poller;
class EventLoop;
class HttpResponse;
class HttpRequest;

using EventCallback     = std::function<void()>;
using ReadEventCallback = std::function<void(TimeStamp)>;

using Functor = std::function<void()>;

struct EventType {
  static const int kNoneEvent  = 0;
  static const int kReadEvent  = EPOLLIN | EPOLLPRI;
  static const int kWriteEvent = EPOLLOUT;
  static const int kErrorEvent = EPOLLERR;
  static const int kCloseEvent = EPOLLHUP;
};

enum class PollerState : std::int8_t { kNew = -1, kAdded = 1, kDeleted = 2 };

using TimerCallback = std::function<void()>;
using TimerEntry    = std::pair<TimeStamp, Timer *>;
using TimerList     = std::set<TimerEntry>;

using ChannelList = std::vector<Channel *>;
using ChannelMap  = std::unordered_map<int, Channel *>;

static constexpr int kTimeScaleFactor       = 1000;
static constexpr int kMillisecondPerSecond  = kTimeScaleFactor;
static constexpr int kMicroSecondsPerSecond = kMillisecondPerSecond * kTimeScaleFactor;
static constexpr int kNanosecondPerSecond   = kMicroSecondsPerSecond * kTimeScaleFactor;

static constexpr size_t kKib = 1024;
static constexpr size_t kMib = kKib * 1024;
static constexpr size_t kGib = kMib * 1024;

static constexpr size_t kDefaultHighWaterMark = kMib * 64;

using ThreadInitCallback = std::function<void(EventLoop *)>;

static constexpr std::string_view kCRLF{ "\r\n" };
static constexpr std::string_view kCRLFCRLF{ "\r\n\r\n" };

enum class Method : int8_t { kInvalid, kGet, kPost, kHead, kPut, kDelete };
enum class Version : int8_t { kUnknown, kHttp10, kHttp11 };

enum class StatusCode : int16_t {
  k100Continue                      = 100,
  k101SwitchingProtocols            = 101,
  k102Processing                    = 102,
  k103EarlyHints                    = 103,
  k200Ok                            = 200,
  k201Created                       = 201,
  k202Accepted                      = 202,
  k203NonAuthoritativeInformation   = 203,
  k204NoContent                     = 204,
  k205ResetContent                  = 205,
  k206PartialContent                = 206,
  k207MultiStatus                   = 207,
  k208AlreadyReported               = 208,
  k226IMUsed                        = 226,
  k300MultipleChoices               = 300,
  k301MovedPermanently              = 301,
  k302Found                         = 302,
  k303SeeOther                      = 303,
  k304NotModified                   = 304,
  k305UseProxy                      = 305,
  k307TemporaryRedirect             = 307,
  k308PermanentRedirect             = 308,
  k400BadRequest                    = 400,
  k401Unauthorized                  = 401,
  k402PaymentRequired               = 402,
  k403Forbidden                     = 403,
  k404NotFound                      = 404,
  k405MethodNotAllowed              = 405,
  k406NotAcceptable                 = 406,
  k407ProxyAuthenticationRequired   = 407,
  k408RequestTimeout                = 408,
  k409Conflict                      = 409,
  k410Gone                          = 410,
  k411LengthRequired                = 411,
  k412PreconditionFailed            = 412,
  k413PayloadTooLarge               = 413,
  k414URITooLong                    = 414,
  k415UnsupportedMediaType          = 415,
  k416RangeNotSatisfiable           = 416,
  k417ExpectationFailed             = 417,
  k418ImATeapot                     = 418,
  k421MisdirectedRequest            = 421,
  k422UnprocessableEntity           = 422,
  k423Locked                        = 423,
  k424FailedDependency              = 424,
  k425TooEarly                      = 425,
  k426UpgradeRequired               = 426,
  k428PreconditionRequired          = 428,
  k429TooManyRequests               = 429,
  k431RequestHeaderFieldsTooLarge   = 431,
  k451UnavailableForLegalReasons    = 451,
  k500InternalServerError           = 500,
  k501NotImplemented                = 501,
  k502BadGateway                    = 502,
  k503ServiceUnavailable            = 503,
  k504GatewayTimeout                = 504,
  k505HTTPVersionNotSupported       = 505,
  k506VariantAlsoNegotiates         = 506,
  k507InsufficientStorage           = 507,
  k508LoopDetected                  = 508,
  k510NotExtended                   = 510,
  k511NetworkAuthenticationRequired = 511
};

enum class CommandType : uint32_t {
  configNoArgs = 0x00000001,
  configTake1  = 0x00000002,
  configTake2  = 0x00000004,
  configTake3  = 0x00000008,
  config1more  = 0x00000010,
  config2more  = 0x00000020,
  configFlag   = 0x00000100,
  configNumber = 0x00000200,
  configString = 0x00000400,
  configSizeT  = 0x00000800,
  configany    = 0x00001000,
  global       = 0x00010000,
  http         = 0x00020000,
  server       = 0x00040000,
  location     = 0x00080000,
};

const uint32_t argsMask = 0x000000FF;
const uint32_t typeMask = 0x0000FF00;

struct ServerCommand {
  std::string name;
  CommandType type;
  size_t confOffset;
  size_t offset;
  std::function<void(const std::vector<std::string> &, void *, size_t)> set;
  std::function<void *(size_t, size_t)> post;
};

using RouteHandler = std::function<void(const HttpRequest &req, HttpResponse *resp)>;

inline CommandType operator|(CommandType first, CommandType second) {
  return static_cast<CommandType>(
      static_cast<std::underlying_type_t<CommandType>>(first)
      | static_cast<std::underlying_type_t<CommandType>>(second)
  );
}

inline CommandType &operator|=(CommandType &first, CommandType second) {
  first = first | second;
  return first;
}

inline bool operator&(CommandType first, CommandType second) {
  return static_cast<bool>(
      static_cast<std::underlying_type_t<CommandType>>(first)
      & static_cast<std::underlying_type_t<CommandType>>(second)
  );
}

inline void freeExtensionStack(STACK_OF(X509_EXTENSION) * stack) {
  if (stack != nullptr) {
    sk_X509_EXTENSION_pop_free(stack, X509_EXTENSION_free);
  }
}

inline void freeStack(STACK_OF(X509) * stack) {
  if (stack != nullptr) {
    sk_X509_pop_free(stack, X509_free);
  }
}

template <typename T, typename Deleter>
using UniqueResource = std::unique_ptr<T, Deleter>;

using UniqueBio       = UniqueResource<BIO, decltype(&BIO_free_all)>;
using UniqueEvpKey    = UniqueResource<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UniqueEvpKeyCtx = UniqueResource<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using UniqueMdCtx     = UniqueResource<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using UniqueX509      = UniqueResource<X509, decltype(&X509_free)>;
using UniqueX509Req   = UniqueResource<X509_REQ, decltype(&X509_REQ_free)>;
using UniqueX509Name  = UniqueResource<X509_NAME, decltype(&X509_NAME_free)>;
using UniqueExtension = UniqueResource<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using UniqueExtensionStack =
    UniqueResource<STACK_OF(X509_EXTENSION), decltype(&freeExtensionStack)>;
using UniqueCurl     = UniqueResource<CURL, decltype(&curl_easy_cleanup)>;
using UniqueCurlList = UniqueResource<curl_slist, decltype(&curl_slist_free_all)>;
struct StoreDeleter {
  void operator()(X509_STORE *store) { X509_STORE_free(store); }
};

struct StoreCtxDeleter {
  void operator()(X509_STORE_CTX *ctx) { X509_STORE_CTX_free(ctx); }
};

struct X509StackDeleter {
  void operator()(STACK_OF(X509) * stack) const {
    if (stack != nullptr) {
      sk_X509_pop_free(stack, X509_free);
    }
  }
};

struct SSLDeleter {
  void operator()(SSL *ssl) const {
    if (ssl != nullptr) {
      SSL_free(ssl);
    }
  }
};

struct SSLCtxDeleter {
  void operator()(SSL_CTX *ctx) {
    if (ctx != nullptr) {
      SSL_CTX_free(ctx);
    }
  }
};

using UniqueStore      = std::unique_ptr<X509_STORE, StoreDeleter>;
using UniqueStoreCtx   = std::unique_ptr<X509_STORE_CTX, StoreCtxDeleter>;
using UniqueStack      = std::unique_ptr<STACK_OF(X509), X509StackDeleter>;
using UniqueSSL        = std::unique_ptr<SSL, SSLDeleter>;
using SharedSslCtx     = std::shared_ptr<SSL_CTX>;

inline UniqueBio createBioFile(const std::string &path, const char *mode) {
  BIO *bio = BIO_new_file(path.c_str(), mode);
  if (bio == nullptr) {
    throw std::runtime_error("Failed to create BIO for file: " + path);
  }
  return { bio, BIO_free_all };
}

inline size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *userp) {
  userp->append(static_cast<char *>(contents), size * nmemb);
  return size * nmemb;
}
} // namespace server
