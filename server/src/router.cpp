#include "include/router.h"

#include "include/config_defaults.h"
#include "include/http_request.h"
#include "include/http_response.h"
#include "include/log.h"
#include "include/types.h"

#include <chrono>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace server {
void Router::addRoute(const LocationConfig &node) {
  std::vector<std::string> segmentVector = splitPath(node.name);
  LocationConfig *currentNode            = &routerNode_;

  LOG_DEBUG("開始處理路由: " + node.name);
  LOG_DEBUG("路徑片段數量: " + std::to_string(segmentVector.size()));

  for (size_t index = 0; index < segmentVector.size(); ++index) {
    const std::string &currentSegment = segmentVector[index];
    LOG_DEBUG("處理第 " + std::to_string(index + 1) + " 個片段: " + currentSegment);

    if (index == segmentVector.size() - 1) {
      // 最後一個片段的處理
      if (currentNode->children.find(currentSegment) != currentNode->children.end()) {
        // 更新已存在的路由，保留子節點
        LOG_DEBUG("檢測到重複的route: " + node.name);
        LOG_DEBUG("開始更新現有路由配置...");

        auto existingChildren = currentNode->children[currentSegment]->children;
        auto childrenCount    = existingChildren.size();
        LOG_DEBUG("保存現有子節點數量: " + std::to_string(childrenCount));

        *(currentNode->children[currentSegment])        = node;
        currentNode->children[currentSegment]->children = existingChildren;

        LOG_DEBUG("路由更新完成: " + node.name);
        LOG_DEBUG(
            "保留原有子節點數量: "
            + std::to_string(currentNode->children[currentSegment]->children.size())
        );
      } else {
        // 新增路由
        LOG_DEBUG("新增路由節點: " + currentSegment);
        currentNode->children[currentSegment]    = std::make_shared<LocationConfig>();
        *(currentNode->children[currentSegment]) = node;
        LOG_DEBUG("新路由節點創建完成");
      }

      LOG_DEBUG("路由處理完成: " + node.name);
      return;
    }

    // 非最後片段的處理
    if (currentNode->children.find(currentSegment) == currentNode->children.end()) {
      LOG_DEBUG("創建中間節點: " + currentSegment);
      currentNode->children[currentSegment] = std::make_shared<LocationConfig>();
    } else {
      LOG_DEBUG("使用已存在的中間節點: " + currentSegment);
    }

    currentNode = currentNode->children[currentSegment].get();
    LOG_DEBUG("移動到下一個節點: " + currentSegment);
  }
}

std::vector<std::string> Router::splitPath(const std::string &path) {
  std::vector<std::string> segmentVector;
  std::string segment;

  if (path == "/") {
    segmentVector.emplace_back("/");
    return segmentVector;
  }

  size_t start = (path[0] == '/') ? 1 : 0;

  for (size_t i = start; i < path.length(); ++i) {
    if (path[i] == '/') {
      if (!segment.empty()) {
        segmentVector.push_back(std::move(segment));
        segment.clear();
      }
    } else {
      segment += path[i];
    }
  }

  if (!segment.empty()) {
    segmentVector.push_back(std::move(segment));
  }

  return segmentVector;
}

void Router::addErrorHandler(StatusCode errorCode, const RouteHandler &func) {
  errorHandlers_[errorCode] = func;
}

void Router::handle(const HttpRequest &req, HttpResponse *resp) {
  LOG_DEBUG("處理請求: " + req.path());
  std::vector<std::string> segmentVector = splitPath(req.path());
  LocationConfig *currentNode            = &routerNode_;

  for (const auto &segment : segmentVector) {
    auto it = currentNode->children.find(segment);
    if (it == currentNode->children.end()) {
      it = currentNode->children.find("*");
      if (it == currentNode->children.end()) {
        handleError(StatusCode::k404NotFound, resp);
        return;
      }
    }
    currentNode = it->second.get();
  }

  if (currentNode->method != Method::kInvalid && req.method() != currentNode->method) {
    LOG_DEBUG("Method is not match");
    handleError(StatusCode::k405MethodNotAllowed, resp);
    return;
  }

  LOG_DEBUG("currentNode的靜態文件的路徑為: " + currentNode->staticFile.string());

  if (!currentNode->staticFile.empty()) {
    LOG_DEBUG("嘗試提供靜態文件: " + currentNode->staticFile.string());
  }

  if (!currentNode->staticFile.empty() && serveStaticFile(currentNode->staticFile, req, resp)) {
    return;
  }

  if (currentNode->handler) {
    LOG_DEBUG("執行路由處理器");
    currentNode->handler(req, resp);
  } else {
    handleError(StatusCode::k500InternalServerError, resp);
  }
}

bool Router::serveStaticFile(
    const std::filesystem::path &staticFilePath,
    const HttpRequest &req,
    HttpResponse *resp
) const {
  LOG_DEBUG("開始處理靜態文件");

  std::filesystem::path normalizedPath;
  try {
    normalizedPath = normalizePath(staticFilePath);
    LOG_DEBUG("標準化後的路徑: " + normalizedPath.string());
  } catch (const std::exception &e) {
    LOG_ERROR("路徑標準化失敗: " + std::string(e.what()));
    handleError(StatusCode::k500InternalServerError);
    return true;
  }

  if (!std::filesystem::exists(normalizedPath)) {
    LOG_DEBUG("靜態檔案不存在");
    return false;
  }

  if (!std::filesystem::is_regular_file(normalizedPath)) {
    handleError(StatusCode::k403Forbidden);
    return true;
  }

  try {
    auto fileSize    = std::filesystem::file_size(normalizedPath);
    auto contentType = getMimeType(normalizedPath.extension().string());
    resp->setContentType(contentType);

    handleCaching(normalizedPath, req, resp);

    if (resp->statusCode() == StatusCode::k304NotModified) {
      return true;
    }

    std::ifstream file(normalizedPath, std::ios::binary);
    if (!file) {
      handleError(StatusCode::k500InternalServerError);
      return true;
    }

    std::string content;
    content.resize(fileSize);
    if (file.read(content.data(), static_cast<std::streamsize>(fileSize))) {
      resp->setBody(std::move(content));
      resp->setStatusCode(StatusCode::k200Ok);
    } else {
      handleError(StatusCode::k500InternalServerError);
    }

    return true;
  } catch (const std::exception &e) {
    LOG_ERROR("Error serving static file: " + std::string(e.what()));
    handleError(StatusCode::k500InternalServerError);
    return true;
  }
}

void Router::initializeMime() {
  std::ifstream mimeFile = std::ifstream("/etc/mime.types");
  if (!mimeFile.is_open()) {
    std::string message = "Cannot open etc/mime.types!";
    LOG_FATAL(message);
    throw std::runtime_error(message);
  }

  std::string line;
  while (std::getline(mimeFile, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::istringstream iss = std::istringstream(line);
    std::string mimeType;
    std::string extension;

    if (!(iss >> mimeType)) {
      continue;
    }

    while (iss >> extension) {
      mimeTypes_["." + extension] = mimeType;
    }
  }

  mimeFile.close();
}

void Router::handleError(StatusCode errorCode, HttpResponse *resp) const {
  auto it = errorHandlers_.find(errorCode);
  if (it != errorHandlers_.end()) {
    HttpRequest emptyReq;
    it->second(emptyReq, resp);
  }
  resp->setStatusCode(errorCode);
}

void Router::handleError(StatusCode errorCode) const {
  HttpResponse resp(Version::kHttp11);
  handleError(errorCode, &resp);
}

std::string Router::getMimeType(const std::string &extension) {
  auto it = mimeTypes_.find(extension);
  if (it == mimeTypes_.end()) {
    std::string message = "Unknown Extension. Extension: " + extension;
    LOG_ERROR(message);
    throw std::invalid_argument(message);
  }

  return it->second;
}

void Router::handleCaching(
    const std::filesystem::path &filePath,
    const HttpRequest &req,
    HttpResponse *resp
) {
  auto lastModTime  = std::filesystem::last_write_time(filePath);
  auto lastModTimeT = std::chrono::system_clock::to_time_t(
      std::chrono::clock_cast<std::chrono::system_clock>(lastModTime)
  );

  char timeBuffer[100];
  size_t timeLength = std::strftime(
      timeBuffer,
      sizeof(timeBuffer),
      "%a, %d %b %Y %H:%M:%S GMT",
      std::gmtime(&lastModTimeT)
  );

  // 添加調試日誌
  LOG_DEBUG("Time buffer length: " + std::to_string(timeLength));
  LOG_DEBUG("Formatted time: " + std::string(timeBuffer));

  std::string timeStr(timeBuffer);
  resp->addHeader("Last-Modified", timeStr);
  resp->addHeader("Cache-Control", "public, max-age=3600");

  if (req.hasHeader("If-Modified-Since")) {
    auto ifModifiedSince = req.getHeader("If-Modified-Since");
    LOG_DEBUG("If-Modified-Since: " + ifModifiedSince);
    LOG_DEBUG("Current time string: " + timeStr);
    if (ifModifiedSince == timeStr) {
      resp->setStatusCode(StatusCode::k304NotModified);
      resp->setBody("");
      return;
    }
  }
}

std::filesystem::path Router::normalizePath(const std::filesystem::path &path) {
  std::string pathStr = path.string();

  LOG_DEBUG("Input path: " + pathStr);
  LOG_DEBUG("Is absolute: " + std::to_string(path.is_absolute()));

  if (path.is_absolute() || pathStr[0] == '/') {
    LOG_DEBUG("檢測到絕對路徑: " + pathStr);
    return path;
  }

  if (path.is_absolute()) {
    LOG_DEBUG("檢測到絕對路徑: " + pathStr);
    return path;
  }

  if (!pathStr.empty() && pathStr[0] == '~') {
    LOG_DEBUG("檢測到家目錄路徑: " + pathStr);
    const char *homeDir = std::getenv("HOME");
    if (homeDir == nullptr) {
      LOG_ERROR("無法獲取家目錄路徑");
      throw std::runtime_error("無法獲取家目錄路徑");
    }
    pathStr = pathStr.substr(1);
    return std::filesystem::path(homeDir) / pathStr.substr(pathStr[0] == '/' ? 1 : 0);
  }

  LOG_DEBUG("轉換相對路徑為絕對路徑: " + pathStr);
  return std::filesystem::absolute(path);
}
} // namespace server
