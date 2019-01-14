#ifndef X509_CRL_HPP_
#define X509_CRL_HPP_

#include <node_api.h>
#include "mbedtls/x509_crl.h"

class X509Crl: public mbedtls_x509_crl
{
public:
    static napi_value Init(napi_env env, napi_value exports);

    static napi_status unwrap(napi_env env, napi_value value, X509Crl **crl);

private:
    explicit X509Crl(napi_env env)
    {
        mbedtls_x509_crl_init(this);
    };
    ~X509Crl(void) { mbedtls_x509_crl_free(this); };

    static napi_value New(napi_env env, napi_callback_info info);
    static void Finalize(napi_env env, void *nativeObject, void *finalize_hint);

    static napi_value Parse(napi_env env, napi_callback_info info);

    static napi_ref sConstructor;
};

#endif // X509_CRL_HPP_
