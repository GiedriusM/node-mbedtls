#ifndef SSL_CONSTANTS_HPP_
#define SSL_CONSTANTS_HPP_

#include <node_api.h>
#include "mbedtls/ssl.h"

class SslConstants
{
public:
    static napi_value Init(napi_env env, napi_value exports);
};

#endif // SSL_CONSTANTS_HPP_
