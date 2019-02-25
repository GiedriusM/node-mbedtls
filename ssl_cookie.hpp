#ifndef SSL_COOKIE_HPP_
#define SSL_COOKIE_HPP_

#include <node_api.h>
#include "mbedtls/ssl_cookie.h"

class SslCookie: public mbedtls_ssl_cookie_ctx
{
public:
    static napi_value Init(napi_env anEnv, napi_value anExport);

    static napi_status unwrap(napi_env anEnv, napi_value aValue, SslCookie **aCookie);

private:
    explicit SslCookie(napi_env anEnv);
    ~SslCookie(void);

    static napi_value New(napi_env anEnv, napi_callback_info anInfo);
    static void Finalize(napi_env anEnv, void *aContext, void *aHint);

    static int SetupRngCb(void *aContext, unsigned char *aBuffer, size_t aLength);
    static napi_value Setup(napi_env anEnv, napi_callback_info anInfo);

    static napi_value Write(napi_env anEnv, napi_callback_info anInfo);
    static napi_value Check(napi_env anEnv, napi_callback_info anInfo);

    static napi_ref sConstructor;

    napi_env    mEnvironment;
    napi_ref    mSetupRngCallback;
};

#endif // SSL_COOKIE_HPP_
