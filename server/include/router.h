#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

namespace server {

class HttpRequest;
class HttpResponse;

class Router {
public:
  static Router &getInstance() {
    static Router instance;
    return instance;
  }

  Router(const Router &)            = delete;
  Router &operator=(const Router &) = delete;

  void addRoute(const LocationConfig &node);
  void addErrorHandler(StatusCode errorCode, const RouteHandler &func);
  void handle(const HttpRequest &req, HttpResponse *resp);

  static void initializeMime();

private:
  Router() { routerNode_ = LocationConfig(); }
  void handleError(StatusCode errorCode) const;
  void handleError(StatusCode errorCode, HttpResponse *resp) const;
  static std::string getMimeType(const std::string &extension);
  static void
  handleCaching(const std::filesystem::path &filePath, const HttpRequest &req, HttpResponse *resp);
  static std::vector<std::string> splitPath(const std::string &path);
  bool serveStaticFile(
      const std::filesystem::path &staticFilePath,
      const HttpRequest &req,
      HttpResponse *resp
  ) const;
  static std::filesystem::path normalizePath(const std::filesystem::path &path);

  LocationConfig routerNode_;
  std::unordered_map<StatusCode, RouteHandler> errorHandlers_;
  static inline std::unordered_map<std::string, std::string> mimeTypes_;
};
} // namespace server
