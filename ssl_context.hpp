#ifndef SSL_CONTEXT_HPP_
#define SSL_CONTEXT_HPP_

#include <node_api.h>
#include "mbedtls/ssl.h"

class SslContext: public mbedtls_ssl_context
{
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    explicit SslContext(napi_env env);
    ~SslContext(void);

    static napi_value New(napi_env env, napi_callback_info info);
    static void Finalize(napi_env env, void *nativeObject, void *finalize_hint);

    static napi_value GetState(napi_env env, napi_callback_info info);

    static napi_value Setup(napi_env env, napi_callback_info info);

    static int BioSendCb(void *ctx, const uint8_t *buf, size_t len);
    static int BioRecvCb(void *ctx, uint8_t *buf, size_t len);
    static int BioRecvTimeoutCb(void *ctx, uint8_t *buf, size_t len, uint32_t timeout);
    static napi_value SetBio(napi_env env, napi_callback_info info);

    static void TimerSetCallback(void *ctx, uint32_t int_ms, uint32_t fin_ms);
    static int TimerGetCallback(void *ctx);
    static napi_value SetTimerCallback(napi_env env, napi_callback_info info);
    static napi_value SessionReset(napi_env env, napi_callback_info info);

    static napi_value Handshake(napi_env env, napi_callback_info info);
    static napi_value Read(napi_env env, napi_callback_info info);
    static napi_value Write(napi_env env, napi_callback_info info);

    static napi_value SendAlertMessage(napi_env env, napi_callback_info info);

    static napi_value CloseNotify(napi_env env, napi_callback_info info);

    static napi_ref sConstructor;

    napi_env    mEnvironment;
    napi_ref    mBioSendCallback;
    napi_ref    mBioRecvCallback;
    napi_ref    mBioRecvTimeoutCallback;
    napi_ref    mTimerSetCallback;
    napi_ref    mTimerGetCallback;
};

#endif // SSL_CONTEXT_HPP_
