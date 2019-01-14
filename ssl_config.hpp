#ifndef SSL_CONFIG_HPP_
#define SSL_CONFIG_HPP_

#include <node_api.h>
#include "mbedtls/ssl.h"

class SslConfig: public mbedtls_ssl_config
{
public:
    static napi_value Init(napi_env env, napi_value exports);

    static napi_status unwrap(napi_env env, napi_value value, SslConfig **config);

private:
    explicit SslConfig(napi_env env):
        mEnvironment(env),
        mRngCallback(nullptr),
        mDbgCallback(nullptr),
        mCookieWriteCallback(nullptr),
        mCookieCheckCallback(nullptr),
        mPskCallback(nullptr)
    {
        mbedtls_ssl_config_init(this);
    };
    ~SslConfig(void) { mbedtls_ssl_config_free(this); };

    static napi_value New(napi_env env, napi_callback_info info);
    static void Finalize(napi_env env, void *nativeObject, void *finalize_hint);

    static napi_value Defaults(napi_env env, napi_callback_info info);

    static napi_value Endpoint(napi_env env, napi_callback_info info);
    static napi_value Transport(napi_env env, napi_callback_info info);
    static napi_value Authmode(napi_env env, napi_callback_info info);

    static int RngCb(void *ctx, unsigned char *buf, size_t len);
    static napi_value Rng(napi_env env, napi_callback_info info);

    static void DbgCb(void *ctx, int level, const char *file, int line,
            const char *msg);
    static napi_value Dbg(napi_env env, napi_callback_info info);

    static int CookieWriteCb(void *ctx, unsigned char **p, unsigned char *end,
            const unsigned char *info, size_t ilen);
    static int CookieCheckCb(void *ctx, const unsigned char *cookie, size_t clen,
            const unsigned char *info, size_t ilen);
    static napi_value DtlsCookies(napi_env env, napi_callback_info info);

    static napi_value Psk(napi_env env, napi_callback_info info);

    static int PskCb(void *ctx, mbedtls_ssl_context *ssl,
            const unsigned char *psk_id, size_t len);
    static napi_value PskCallback(napi_env env, napi_callback_info info);

    static napi_value CaChain(napi_env env, napi_callback_info info);
    static napi_value OwnCert(napi_env env, napi_callback_info info);

    static napi_ref sConstructor;

    napi_env    mEnvironment;
    napi_ref    mRngCallback;
    napi_ref    mDbgCallback;
    napi_ref    mCookieWriteCallback;
    napi_ref    mCookieCheckCallback;
    napi_ref    mPskCallback;
};

#endif // SSL_CONFIG_HPP_
