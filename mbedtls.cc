#include <node_api.h>

#include "ssl_constants.hpp"
#include "ssl_config.hpp"
#include "ssl_context.hpp"


napi_value Init(napi_env env, napi_value exports)
{
    SslConstants::Init(env, exports);
    SslConfig::Init(env, exports);
    SslContext::Init(env, exports);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
