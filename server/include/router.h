#pragma once

#include "include/config_defaults.h"
#include "include/types.h"

#include <string_view>
#include <unordered_map>

namespace server {

class HttpRequest;
class HttpResponse;

class Router final {
public:
  static Router &getInstance();

  Router(const Router &)            = delete;
  Router &operator=(const Router &) = delete;

  void addRoute(const LocationConfig &node);
  void addErrorHandler(StatusCode errorCode, const RouteHandler &func);
  void handle(const HttpRequest &req, HttpResponse *resp);

  static void initializeMime();

private:
  Router();
  ~Router() = default;

  static constexpr size_t MAX_PATH_SEGMENTS = 32;
  static constexpr size_t PATH_BUFFER_SIZE  = 256;

  void handleError(StatusCode errorCode) const;
  void handleError(StatusCode errorCode, HttpResponse *resp) const;
  [[nodiscard]] static std::string_view getMimeType(std::string_view extension) noexcept;
  void
  handleCaching(const std::filesystem::path &filePath, const HttpRequest &req, HttpResponse *resp)
      const;
  static size_t splitPath(std::string_view path, std::string_view *segments) noexcept;
  bool serveStaticFile(
      const std::filesystem::path &staticFilePath,
      const HttpRequest &req,
      HttpResponse *resp
  ) const;
  [[nodiscard]] static std::filesystem::path normalizePath(const std::filesystem::path &path);
  [[nodiscard]] const LocationConfig *findMatchingRoute(const HttpRequest &req) const noexcept;

  LocationConfig rootNode_;
  std::unordered_map<StatusCode, RouteHandler> errorHandlers_;
  static inline std::unordered_map<std::string, std::string> mimeTypes_;
  mutable std::array<char, PATH_BUFFER_SIZE> pathBuffer_;
};

} // namespace server
