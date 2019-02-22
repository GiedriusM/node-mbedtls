#include "ssl_cookie.hpp"

#include <assert.h>
#include <string.h>

#include "mbedtls_utils.h"


static napi_status rereference(napi_env anEnv, napi_ref &aRef, napi_value aVal)
{
    napi_status status;

    if (aRef != nullptr)
    {
        status = napi_delete_reference(anEnv, aRef);
        aRef = nullptr;

        if (status != napi_ok)
        {
            return status;
        }
    }

    if (aVal != nullptr)
    {
        status = napi_create_reference(anEnv, aVal, 1, &aRef);

        if (status != napi_ok)
        {
            return status;
        }
    }

    return napi_ok;
}

napi_ref SslCookie::sConstructor;

napi_value SslCookie::Init(napi_env anEnv, napi_value anExport)
{
    napi_status status;
    const uint32_t nProperties = 3;
    napi_property_descriptor properties[nProperties] = {
        DECLARE_NAPI_METHOD("setup", Setup),
        DECLARE_NAPI_METHOD("write", Write),
        DECLARE_NAPI_METHOD("check", Check),
    };
    napi_value constructor;

    status = napi_define_class(anEnv, "mbedtls_ssl_cookie", NAPI_AUTO_LENGTH,
                               New, nullptr, nProperties, properties, &constructor);
    assert(status == napi_ok);

    status = napi_create_reference(anEnv, constructor, 1, &sConstructor);
    assert(status == napi_ok);

    status = napi_set_named_property(anEnv, anExport, "SSLCookie", constructor);
    assert(status == napi_ok);

    return anExport;
}

napi_status SslCookie::unwrap(napi_env anEnv, napi_value aValue, SslCookie **aCookie)
{
    napi_status status;
    napi_value constructor;
    bool isCookie = false;

    *aCookie = nullptr;

    status = napi_get_reference_value(anEnv, sConstructor, &constructor);
    assert(status == napi_ok);

    status = napi_instanceof(anEnv, aValue, constructor, &isCookie);
    assert(status == napi_ok);
    if (!isCookie)
    {
        return napi_invalid_arg;
    }

    status = napi_unwrap(anEnv, aValue, reinterpret_cast<void **>(aCookie));
    assert(status == napi_ok);

    return napi_ok;
}

SslCookie::SslCookie(napi_env anEnv):
    mEnvironment(anEnv),
    mSetupRngCallback(nullptr)
{
    mbedtls_ssl_cookie_init(this);
}

SslCookie::~SslCookie(void)
{
    mbedtls_ssl_cookie_free(this);
}

napi_value SslCookie::New(napi_env anEnv, napi_callback_info anInfo)
{
    napi_status status;
    napi_value target;

    status = napi_get_new_target(anEnv, anInfo, &target);
    assert(status == napi_ok);

    bool isConstructor = target != nullptr;

    if (isConstructor) { // called with new
        napi_value jsthis;
        status = napi_get_cb_info(anEnv, anInfo, nullptr, nullptr, &jsthis, nullptr);
        assert(status == napi_ok);

        SslCookie *obj = new SslCookie(anEnv);

        status = napi_wrap(anEnv, jsthis, reinterpret_cast<void*>(obj),
                Finalize, nullptr, nullptr);
        assert(status == napi_ok);

        return jsthis;
    } else { // called as function
        napi_value constructor;
        status = napi_get_reference_value(anEnv, sConstructor, &constructor);
        assert(status == napi_ok);

        napi_value instance;
        status = napi_new_instance(anEnv, constructor, 0, nullptr, &instance);
        assert(status == napi_ok);

        return instance;
    }
}

void SslCookie::Finalize(napi_env anEnv, void *aContext, void *aHint)
{
    delete reinterpret_cast<SslCookie *>(aContext);
}

int SslCookie::SetupRngCb(void *aContext, unsigned char *aBuffer, size_t aLength)
{
    napi_status status;
    SslCookie *self = reinterpret_cast<SslCookie *>(aContext);
    const int argc = 1;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;
    void *buf;
    int ret;

    // prepare args: buffer, length
    status = napi_create_buffer(self->mEnvironment, aLength, &buf, &argv[0]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mSetupRngCallback, &func);
    assert(status == napi_ok);

    memset(buf, 0, aLength);

    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    assert(status == napi_ok);

    memcpy(aBuffer, buf, aLength);

    // retrieve return value
    status = napi_get_value_int32(self->mEnvironment, jsret, &ret);
    assert(status == napi_ok);

    return ret;
}

napi_value SslCookie::Setup(napi_env anEnv, napi_callback_info aInfo)
{
    napi_status status;
    napi_value jsthis;
    SslCookie* self;
    size_t argc = 1;
    napi_value args[1];
    napi_valuetype type;
    napi_value jsret;
    int ret;

    status = napi_get_cb_info(anEnv, aInfo, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), callback
    if (argc < 1)
    {
        status = napi_throw_type_error(anEnv, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(anEnv, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(anEnv, args[0], &type);
    assert(status == napi_ok);
    if (type != napi_function)
    {
        status = napi_throw_type_error(anEnv, nullptr, "Function expected");
        return nullptr;
    }

    // call
    status = rereference(anEnv, self->mSetupRngCallback, args[0]);
    assert(status == napi_ok);

    ret = mbedtls_ssl_cookie_setup(self, args[0] ? SetupRngCb : nullptr, self);

    // return
    status = napi_create_int32(anEnv, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslCookie::Write(napi_env anEnv, napi_callback_info anInfo)
{
    napi_status status;
    napi_value jsthis;
    SslCookie* self;
    size_t argc = 2;
    napi_value args[2];
    napi_value jsret;
    bool isBuffer;
    uint8_t *cookie;
    size_t cookieLen;
    uint8_t *info;
    size_t infoLen;
    uint8_t *ptr;
    int ret;

    status = napi_get_cb_info(anEnv, anInfo, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), cookie, info
    if (argc < 2)
    {
        status = napi_throw_type_error(anEnv, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(anEnv, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_is_buffer(anEnv, args[0], &isBuffer);
    assert(status == napi_ok);
    if (isBuffer)
    {
        status = napi_get_buffer_info(anEnv, args[0],
                reinterpret_cast<void **>(&cookie), &cookieLen);
        assert(status == napi_ok);
    }
    else
    {
        status = napi_throw_type_error(anEnv, nullptr, "cookie must be a buffer");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_is_buffer(anEnv, args[1], &isBuffer);
    assert(status == napi_ok);
    if (isBuffer)
    {
        status = napi_get_buffer_info(anEnv, args[1],
                reinterpret_cast<void **>(&info), &infoLen);
        assert(status == napi_ok);
    }
    else
    {
        status = napi_throw_type_error(anEnv, nullptr, "info must be a buffer");
        assert(status == napi_ok);
        return nullptr;
    }

    // call
    ptr = cookie;
    ret = mbedtls_ssl_cookie_write(self, &ptr, cookie + cookieLen, info, infoLen);

    if (ret == 0)
    {
        ret = ptr - cookie;
    }

    // return
    status = napi_create_int32(anEnv, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslCookie::Check(napi_env anEnv, napi_callback_info anInfo)
{
    napi_status status;
    napi_value jsthis;
    SslCookie* self;
    size_t argc = 2;
    napi_value args[2];
    napi_value jsret;
    bool isBuffer;
    uint8_t *cookie;
    size_t cookieLen;
    uint8_t *info;
    size_t infoLen;
    int ret;

    status = napi_get_cb_info(anEnv, anInfo, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), cookie, info
    if (argc < 2)
    {
        status = napi_throw_type_error(anEnv, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(anEnv, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_is_buffer(anEnv, args[0], &isBuffer);
    assert(status == napi_ok);
    if (isBuffer)
    {
        status = napi_get_buffer_info(anEnv, args[0],
                reinterpret_cast<void **>(&cookie), &cookieLen);
        assert(status == napi_ok);
    }
    else
    {
        status = napi_throw_type_error(anEnv, nullptr, "cookie must be a buffer");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_is_buffer(anEnv, args[1], &isBuffer);
    assert(status == napi_ok);
    if (isBuffer)
    {
        status = napi_get_buffer_info(anEnv, args[1],
                reinterpret_cast<void **>(&info), &infoLen);
        assert(status == napi_ok);
    }
    else
    {
        status = napi_throw_type_error(anEnv, nullptr, "info must be a buffer");
        assert(status == napi_ok);
        return nullptr;
    }

    // call
    ret = mbedtls_ssl_cookie_check(self, cookie, cookieLen, info, infoLen);

    // return
    status = napi_create_int32(anEnv, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}
