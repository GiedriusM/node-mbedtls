#include "ssl_constants.hpp"
#include <assert.h>

#define DECLARE_NAPI_CONSTANT(name, value)  \
      { name, 0, 0, get_constant, 0, 0, napi_default, (void*)value }


static napi_value get_constant(napi_env env, napi_callback_info info)
{
    napi_status status;
    int32_t data;
    napi_value jsvalue;

    status = napi_get_cb_info(env, info, nullptr, nullptr, nullptr,
            reinterpret_cast<void**>(&data));
    assert(status == napi_ok);

    status = napi_create_int32(env, data, &jsvalue);
    assert(status == napi_ok);
    return jsvalue;
}

napi_value SslConstants::Init(napi_env env, napi_value exports)
{
    napi_status status;
    const uint32_t num_properties = 9;
    napi_property_descriptor properties[num_properties] = {
        DECLARE_NAPI_CONSTANT("SSL_TRANSPORT_STREAM", MBEDTLS_SSL_TRANSPORT_STREAM),
        DECLARE_NAPI_CONSTANT("SSL_TRANSPORT_DATAGRAM", MBEDTLS_SSL_TRANSPORT_DATAGRAM),
        DECLARE_NAPI_CONSTANT("SSL_IS_CLIENT", MBEDTLS_SSL_IS_CLIENT),
        DECLARE_NAPI_CONSTANT("SSL_IS_SERVER", MBEDTLS_SSL_IS_SERVER),
        DECLARE_NAPI_CONSTANT("SSL_VERIFY_NONE", MBEDTLS_SSL_VERIFY_NONE),
        DECLARE_NAPI_CONSTANT("SSL_VERIFY_OPTIONAL", MBEDTLS_SSL_VERIFY_OPTIONAL),
        DECLARE_NAPI_CONSTANT("SSL_VERIFY_REQUIRED", MBEDTLS_SSL_VERIFY_REQUIRED),
        DECLARE_NAPI_CONSTANT("SSL_PRESET_DEFAULT", MBEDTLS_SSL_PRESET_DEFAULT),
        DECLARE_NAPI_CONSTANT("SSL_PRESET_SUITEB", MBEDTLS_SSL_PRESET_SUITEB),
    };

    status = napi_define_properties(env, exports, num_properties, properties);
    assert(status == napi_ok);

    return exports;
}
