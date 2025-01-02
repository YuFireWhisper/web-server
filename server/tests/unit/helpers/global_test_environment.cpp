#include "tests/unit/helpers/global_test_environment.h"

#include "include/config_commands.h"
#include "include/config_defaults.h"
#include "include/config_manager.h"

namespace server::testing {
void GlobalTestEnvironment::initialConfigManager() {
  auto &manager = ConfigManager::getInstance();

  manager.registerCommands(getAllCommands());

  ConfigContext context;
  context.now = kGlobalOffset;

  context.globalContext   = new GlobalContext();
  context.httpContext     = new HttpContext();
  context.serverContext   = new ServerContext();
  context.locationContext = new LocationContext();

  auto globalConfig           = std::make_unique<GlobalConfig>();
  context.globalContext->conf = globalConfig.release();

  auto httpConfig             = std::make_unique<HttpConfig>();
  context.httpContext->conf   = httpConfig.release();
  context.httpContext->parent = context.globalContext;

  auto serverConfig             = std::make_unique<ServerConfig>();
  context.serverContext->conf   = serverConfig.release();
  context.serverContext->parent = context.httpContext;

  auto locationConfig             = std::make_unique<LocationConfig>();
  context.locationContext->conf   = locationConfig.release();
  context.locationContext->parent = context.serverContext;

  manager.setCurrentText(context);
}
} // namespace server::testing
