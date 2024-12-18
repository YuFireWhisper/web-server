#include "include/config_defaults.h"
#include "include/types.h"

namespace server {

class HttpRequest;
class HttpResponse;

class Router {
public:
  Router(RouterConfig node);

  Router(const Router &)            = delete;
  Router &operator=(const Router &) = delete;

  void addRoute(const RouterConfig &node);
  void addErrorHandler(StatusCode errorCode, const RouteHandler &func);
  void handle(const HttpRequest &req, HttpResponse *resp);

  static void initializeMime();

private:
  void handleError(StatusCode errorCode) const;
  static std::string getMimeType(const std::string &extension);
  static void
  handleCaching(const std::filesystem::path &filePath, const HttpRequest &req, HttpResponse *resp);
  static std::vector<std::string> splitPath(const std::string &path);
  bool serveStaticFile(
      const std::filesystem::path &staticFilePath,
      const HttpRequest &req,
      HttpResponse *resp
  ) const;

  RouterConfig routerNode_;
  std::unordered_map<StatusCode, RouteHandler> errorHandlers_;
  static inline std::unordered_map<std::string, std::string> mimeTypes_;
};
} // namespace server
