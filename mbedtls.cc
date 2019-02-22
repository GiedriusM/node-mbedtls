#include <node_api.h>

#include "ssl_constants.hpp"
#include "ssl_config.hpp"
#include "ssl_context.hpp"
#include "ssl_cookie.hpp"
#include "x509_crt.hpp"
#include "x509_crl.hpp"
#include "pk_context.hpp"


napi_value Init(napi_env env, napi_value exports)
{
    SslConstants::Init(env, exports);
    SslConfig::Init(env, exports);
    SslContext::Init(env, exports);
    SslCookie::Init(env, exports);
    X509Crt::Init(env, exports);
    X509Crl::Init(env, exports);
    PKContext::Init(env, exports);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
