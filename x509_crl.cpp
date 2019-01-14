#include "x509_crl.hpp"

#include <assert.h>

#include "mbedtls_utils.h"


napi_ref X509Crl::sConstructor;

napi_value X509Crl::Init(napi_env env, napi_value exports)
{
    napi_status status;
    const uint32_t num_properties = 1;
    napi_property_descriptor properties[num_properties] = {
        DECLARE_NAPI_METHOD("parse", Parse),
    };
    napi_value cons;

    status = napi_define_class(env, "mbedtls_x509_crl", NAPI_AUTO_LENGTH,
                               New, nullptr, num_properties, properties, &cons);
    assert(status == napi_ok);

    status = napi_create_reference(env, cons, 1, &sConstructor);
    assert(status == napi_ok);

    status = napi_set_named_property(env, exports, "X509Crl", cons);
    assert(status == napi_ok);

    return exports;
}

napi_status X509Crl::unwrap(napi_env env, napi_value value, X509Crl **crl)
{
    napi_status status;
    napi_value cons;
    napi_valuetype type;
    bool is_instance = false;

    status = napi_get_reference_value(env, sConstructor, &cons);
    assert(status == napi_ok);

    status = napi_typeof(env, value, &type);
    assert(status == napi_ok);

    status = napi_instanceof(env, value, cons, &is_instance);
    assert(status == napi_ok);

    if (type == napi_null)
    {
        *crl = nullptr;
    }
    else if (is_instance)
    {
        status = napi_unwrap(env, value, reinterpret_cast<void **>(crl));
        assert(status == napi_ok);
    }
    else
    {
        return napi_invalid_arg;
    }

    return status;
}

napi_value X509Crl::New(napi_env env, napi_callback_info info)
{
    napi_status status;

    napi_value target;
    status = napi_get_new_target(env, info, &target);
    assert(status == napi_ok);

    bool is_constructor = target != nullptr;

    if (is_constructor) { // called with new
        napi_value jsthis;
        status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
        assert(status == napi_ok);

        X509Crl *obj = new X509Crl(env);

        status = napi_wrap(env, jsthis, reinterpret_cast<void*>(obj),
                           Finalize, nullptr,
                           nullptr);
        assert(status == napi_ok);

        return jsthis;
    } else { // called as function
        napi_value cons;
        status = napi_get_reference_value(env, sConstructor, &cons);
        assert(status == napi_ok);

        napi_value instance;
        status = napi_new_instance(env, cons, 0, nullptr, &instance);
        assert(status == napi_ok);

        return instance;
    }
}

void X509Crl::Finalize(napi_env env, void *nativeObject, void *finalize_hint)
{
    delete reinterpret_cast<X509Crl *>(nativeObject);
}

napi_value X509Crl::Parse(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 1;
    napi_value args[argc];
    napi_value jsret;
    X509Crl* self;
    bool is_buffer;
    uint8_t *buf;
    size_t buf_len;
    int ret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), buffer
    if (argc < 1)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_is_buffer(env, args[0], &is_buffer);
    assert(status == napi_ok);
    if (is_buffer)
    {
        status = napi_get_buffer_info(env, args[0],
                reinterpret_cast<void **>(&buf), &buf_len);
        assert(status == napi_ok);
    }
    else
    {
        status = napi_throw_type_error(env, nullptr, "Buffer expected");
        assert(status == napi_ok);
        return nullptr;
    }

    // call
    ret = mbedtls_x509_crl_parse(self, buf, buf_len);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}
