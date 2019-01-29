#ifndef PK_CONTEXT_HPP_
#define PK_CONTEXT_HPP_

#include <node_api.h>
#include "mbedtls/pk.h"

class PKContext: public mbedtls_pk_context
{
public:
    static napi_value Init(napi_env env, napi_value exports);

    static napi_status unwrap(napi_env env, napi_value value, PKContext **crl);

private:
    explicit PKContext(napi_env env);
    ~PKContext(void);

    static napi_value New(napi_env env, napi_callback_info info);
    static void Finalize(napi_env env, void *nativeObject, void *finalize_hint);

    static napi_value ParseKey(napi_env env, napi_callback_info info);

    static napi_ref sConstructor;
};

#endif // PK_CONTEXT_HPP_
