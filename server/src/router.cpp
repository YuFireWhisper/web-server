#include "include/router.h"

#include "include/http_request.h"
#include "include/http_response.h"
#include "include/log.h"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace server {

Router &Router::getInstance() {
  static Router instance;
  return instance;
}

Router::Router() {
  LOG_DEBUG("初始化Router實例");
  rootNode_.name = "/";
}

void Router::addRoute(const LocationConfig &node) {
  LOG_DEBUG("開始添加路由: " + node.name);
  std::string_view segments[MAX_PATH_SEGMENTS];
  const size_t segmentCount = splitPath(node.name, segments);

  LOG_DEBUG("路徑切分結果:");
  for (size_t i = 0; i < segmentCount; ++i) {
    LOG_DEBUG("  段[" + std::to_string(i) + "]: " + std::string(segments[i]));
  }

  LocationConfig *currentNode = &rootNode_;
  LOG_DEBUG("從根節點開始處理，根節點名稱: " + rootNode_.name);

  for (size_t i = 0; i < segmentCount; ++i) {
    const auto &segment = segments[i];
    auto segmentStr     = std::string(segment);
    LOG_DEBUG("處理段[" + std::to_string(i) + "]: " + segmentStr);

    if (i == segmentCount - 1) {
      LOG_DEBUG("到達最後一段，配置終端節點");
      auto &targetNode = currentNode->children[segmentStr];
      if (!targetNode) {
        LOG_DEBUG("創建新的終端節點");
        targetNode = std::make_shared<LocationConfig>();
      } else {
        LOG_DEBUG("更新已存在的終端節點");
      }

      auto existingChildren = targetNode->children;
      LOG_DEBUG("保存現有子節點數: " + std::to_string(existingChildren.size()));

      *targetNode          = node;
      targetNode->children = std::move(existingChildren);
      LOG_DEBUG("終端節點配置完成");
      return;
    }

    auto &nextNode = currentNode->children[segmentStr];
    if (!nextNode) {
      LOG_DEBUG("創建新的中間節點: " + segmentStr);
      nextNode       = std::make_shared<LocationConfig>();
      nextNode->name = segmentStr;
    } else {
      LOG_DEBUG("使用已存在的中間節點: " + segmentStr);
    }
    currentNode = nextNode.get();
  }
}

size_t Router::splitPath(std::string_view path, std::string_view *segments) const noexcept {
  LOG_DEBUG("開始分割路徑: " + std::string(path));
  size_t count = 0;

  if (path == "/") {
    LOG_DEBUG("根路徑處理");
    segments[0] = path;
    return 1;
  }

  size_t start        = path[0] == '/' ? 1 : 0;
  size_t pos          = start;
  const size_t length = path.length();

  while (pos < length && count < MAX_PATH_SEGMENTS) {
    if (path[pos] == '/') {
      if (pos > start) {
        segments[count] = path.substr(start, pos - start);
        LOG_DEBUG("分割得到段[" + std::to_string(count) + "]: " + std::string(segments[count]));
        ++count;
      }
      start = pos + 1;
    }
    ++pos;
  }

  if (start < length && count < MAX_PATH_SEGMENTS) {
    segments[count] = path.substr(start);
    LOG_DEBUG("分割得到最後一段[" + std::to_string(count) + "]: " + std::string(segments[count]));
    ++count;
  }

  LOG_DEBUG("路徑分割完成，共 " + std::to_string(count) + " 段");
  return count;
}

const LocationConfig *Router::findMatchingRoute(const HttpRequest &req) const noexcept {
  LOG_DEBUG("開始查找匹配路由，請求路徑: " + std::string(req.path()));

  std::string_view segments[MAX_PATH_SEGMENTS];
  const size_t segmentCount = splitPath(req.path(), segments);

  const LocationConfig *currentNode = &rootNode_;
  LOG_DEBUG("從根節點開始查找，根節點名稱: " + currentNode->name);

  for (size_t i = 0; i < segmentCount; ++i) {
    const auto &segment = segments[i];
    LOG_DEBUG("嘗試匹配段[" + std::to_string(i) + "]: " + std::string(segment));

    auto it = currentNode->children.find(std::string(segment));
    if (it == currentNode->children.end()) {
      LOG_DEBUG("未找到精確匹配，嘗試通配符匹配");
      it = currentNode->children.find("*");
      if (it == currentNode->children.end()) {
        LOG_DEBUG("未找到匹配的節點，返回nullptr");
        return nullptr;
      }
      LOG_DEBUG("找到通配符匹配");
    } else {
      LOG_DEBUG("找到精確匹配");
    }
    currentNode = it->second.get();
    LOG_DEBUG("移動到下一個節點: " + currentNode->name);
  }

  LOG_DEBUG("找到最終匹配節點: " + currentNode->name);
  return currentNode;
}

void Router::handle(const HttpRequest &req, HttpResponse *resp) {
  LOG_DEBUG(
      "開始處理請求，方法: " + std::string(HttpRequest::methodString(req.method()))
      + ", 路徑: " + std::string(req.path())
  );

  const LocationConfig *matchingNode = findMatchingRoute(req);

  if (matchingNode == nullptr) {
    LOG_DEBUG("未找到匹配的路由，返回404");
    handleError(StatusCode::k404NotFound, resp);
    return;
  }

  LOG_DEBUG("找到匹配的路由節點: " + matchingNode->name);

  if (matchingNode->method != Method::kInvalid && req.method() != matchingNode->method) {
    LOG_DEBUG("請求方法不匹配，返回405");
    handleError(StatusCode::k405MethodNotAllowed, resp);
    return;
  }

  if (!matchingNode->staticFile.empty()) {
    LOG_DEBUG("發現靜態文件配置: " + matchingNode->staticFile.string());
    if (serveStaticFile(matchingNode->staticFile, req, resp)) {
      LOG_DEBUG("靜態文件處理完成");
      return;
    }
    LOG_DEBUG("靜態文件處理失敗，繼續檢查handler");
  }

  if (matchingNode->handler) {
    LOG_DEBUG("執行自定義處理器");
    matchingNode->handler(req, resp);
    return;
  }

  LOG_DEBUG("無可用的處理方式，返回500");
  handleError(StatusCode::k500InternalServerError, resp);
}

bool Router::serveStaticFile(
    const std::filesystem::path &staticFilePath,
    const HttpRequest &req,
    HttpResponse *resp
) const {
  LOG_DEBUG("開始處理靜態文件: " + staticFilePath.string());

  try {
    const auto normalizedPath = normalizePath(staticFilePath);
    LOG_DEBUG("規範化後的路徑: " + normalizedPath.string());

    if (!std::filesystem::exists(normalizedPath)) {
      LOG_DEBUG("文件不存在: " + normalizedPath.string());
      return false;
    }

    LOG_DEBUG("文件存在");

    if (!std::filesystem::is_regular_file(normalizedPath)) {
      LOG_DEBUG("不是普通文件，返回403");
      handleError(StatusCode::k403Forbidden, resp);
      return true;
    }
    LOG_DEBUG("確認是普通文件");

    const auto fileSize = std::filesystem::file_size(normalizedPath);
    LOG_DEBUG("文件大小: " + std::to_string(fileSize));

    auto extension = normalizedPath.extension().string();
    LOG_DEBUG("文件擴展名: " + extension);

    resp->setContentType(std::string(getMimeType(extension)));
    LOG_DEBUG("設置Content-Type完成");

    handleCaching(normalizedPath, req, resp);
    if (resp->statusCode() == StatusCode::k304NotModified) {
      LOG_DEBUG("文件未修改，返回304");
      return true;
    }

    std::ifstream file(normalizedPath, std::ios::binary);
    if (!file) {
      LOG_DEBUG("無法打開文件，返回500");
      handleError(StatusCode::k500InternalServerError, resp);
      return true;
    }
    LOG_DEBUG("成功打開文件");

    std::string content;
    content.resize(fileSize);

    if (file.read(content.data(), static_cast<std::streamsize>(fileSize))) {
      LOG_DEBUG("成功讀取文件內容");
      resp->setBody(std::move(content));
      resp->setStatusCode(StatusCode::k200Ok);
      return true;
    }

    LOG_DEBUG("讀取文件失敗，返回500");
    handleError(StatusCode::k500InternalServerError, resp);
    return true;

  } catch (const std::exception &e) {
    LOG_ERROR("處理靜態文件時發生錯誤: " + std::string(e.what()));
    handleError(StatusCode::k500InternalServerError, resp);
    return true;
  }
}

void Router::initializeMime() {
  std::ifstream mimeFile("/etc/mime.types");
  if (!mimeFile) {
    throw std::runtime_error("Cannot open /etc/mime.types");
  }

  std::string line;

  while (std::getline(mimeFile, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::istringstream iss(line);
    std::string mimeType;
    std::string extension;

    if (iss >> mimeType) {
      while (iss >> extension) {
        server::Router::mimeTypes_["." + extension] = mimeType;
      }
    }
  }
}

void Router::addErrorHandler(StatusCode errorCode, const RouteHandler &func) {
  errorHandlers_[errorCode] = func;
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

std::string_view Router::getMimeType(std::string_view extension) const noexcept {
  auto it = mimeTypes_.find(std::string(extension));
  return it != mimeTypes_.end() ? std::string_view(it->second) : "application/octet-stream";
}

void Router::handleCaching(
    const std::filesystem::path &filePath,
    const HttpRequest &req,
    HttpResponse *resp
) const {
  const auto lastModTime  = std::filesystem::last_write_time(filePath);
  const auto lastModTimeT = std::chrono::system_clock::to_time_t(
      std::chrono::clock_cast<std::chrono::system_clock>(lastModTime)
  );

  std::strftime(
      pathBuffer_.data(),
      pathBuffer_.size(),
      "%a, %d %b %Y %H:%M:%S GMT",
      std::gmtime(&lastModTimeT)
  );

  const std::string timeStr(pathBuffer_.data());
  resp->addHeader("Last-Modified", timeStr);
  resp->addHeader("Cache-Control", "public, max-age=3600");

  if (req.hasHeader("If-Modified-Since") && req.getHeader("If-Modified-Since") == timeStr) {
    resp->setStatusCode(StatusCode::k304NotModified);
    resp->setBody("");
  }
}

std::filesystem::path Router::normalizePath(const std::filesystem::path &path) const {
  LOG_DEBUG("正在規範化路徑: " + path.string());

  if (path.is_absolute() || path.string()[0] == '/') {
    LOG_DEBUG("已經是絕對路徑，直接返回");
    return path;
  }

  const std::string pathStr = path.string();
  if (!pathStr.empty() && pathStr[0] == '~') {
    LOG_DEBUG("處理波浪號路徑");
    const char *homeDir = std::getenv("HOME");
    if (homeDir == nullptr) {
      throw std::runtime_error("無法獲取HOME目錄");
    }
    size_t skipLength = (pathStr.length() > 1 && pathStr[1] == '/') ? 2 : 1;
    return std::filesystem::path(homeDir) / pathStr.substr(skipLength);
  }

  LOG_DEBUG("處理相對路徑");
  return std::filesystem::absolute(path);
}

} // namespace server
