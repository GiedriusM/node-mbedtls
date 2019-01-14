#ifndef X509_CRT_HPP_
#define X509_CRT_HPP_

#include <node_api.h>
#include "mbedtls/x509_crt.h"

class X509Crt: public mbedtls_x509_crt
{
public:
    static napi_value Init(napi_env env, napi_value exports);

    static napi_status unwrap(napi_env env, napi_value value, X509Crt **crt);

private:
    explicit X509Crt(napi_env env)
    {
        mbedtls_x509_crt_init(this);
    };
    ~X509Crt(void) { mbedtls_x509_crt_free(this); };

    static napi_value New(napi_env env, napi_callback_info info);
    static void Finalize(napi_env env, void *nativeObject, void *finalize_hint);

    static napi_value Parse(napi_env env, napi_callback_info info);

    static napi_ref sConstructor;
};

#endif // X509_CRT_HPP_
