#include "ssl_config.hpp"

#include <assert.h>
#include <string.h>

#include "x509_crt.hpp"
#include "x509_crl.hpp"
#include "pk_context.hpp"
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

napi_ref SslConfig::sConstructor;

napi_value SslConfig::Init(napi_env env, napi_value exports)
{
    napi_status status;
    const uint32_t num_properties = 9;
    napi_property_descriptor properties[num_properties] = {
        DECLARE_NAPI_METHOD("defaults", Defaults),
        DECLARE_NAPI_METHOD("authmode", Authmode),
        DECLARE_NAPI_METHOD("rng", Rng),
        DECLARE_NAPI_METHOD("dbg", Dbg),
        DECLARE_NAPI_METHOD("dtls_cookies", DtlsCookies),
        DECLARE_NAPI_METHOD("psk", Psk),
        DECLARE_NAPI_METHOD("psk_cb", PskCallback),
        DECLARE_NAPI_METHOD("ca_chain", CaChain),
        DECLARE_NAPI_METHOD("own_cert", OwnCert),
    };
    napi_value cons;

    status = napi_define_class(env, "mbedtls_ssl_config", NAPI_AUTO_LENGTH,
                               New, nullptr, num_properties, properties, &cons);
    assert(status == napi_ok);

    status = napi_create_reference(env, cons, 1, &sConstructor);
    assert(status == napi_ok);

    status = napi_set_named_property(env, exports, "SSLConfig", cons);
    assert(status == napi_ok);

    return exports;
}

napi_status SslConfig::unwrap(napi_env env, napi_value value, SslConfig **config)
{
    napi_status status;
    napi_value cons;
    bool is_config = false;

    *config = nullptr;

    status = napi_get_reference_value(env, sConstructor, &cons);
    assert(status == napi_ok);

    status = napi_instanceof(env, value, cons, &is_config);
    assert(status == napi_ok);
    if (!is_config)
    {
        return napi_invalid_arg;
    }

    status = napi_unwrap(env, value, reinterpret_cast<void **>(config));
    assert(status == napi_ok);

    return napi_ok;
}

napi_value SslConfig::New(napi_env env, napi_callback_info info)
{
    napi_status status;

    napi_value target;
    status = napi_get_new_target(env, info, &target);
    assert(status == napi_ok);

    bool is_constructor = target != nullptr;

    if (is_constructor) { // called with new
        size_t argc = 1;
        napi_value args[1];
        napi_value jsthis;
        status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
        assert(status == napi_ok);

        SslConfig *obj = new SslConfig(env);

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

void SslConfig::Finalize(napi_env env, void *nativeObject, void *finalize_hint)
{
    delete reinterpret_cast<SslConfig *>(nativeObject);
}

napi_value SslConfig::Defaults(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    SslConfig* self;
    size_t argc = 3;
    napi_value args[3];
    int endpoint, transport, preset;
    int ret;
    napi_value jsret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // Get params: self (this), endpoint, transport and preset
    if (argc < 3)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_get_value_int32(env, args[0], &endpoint);
    if (status == napi_number_expected)
    {
        status = napi_throw_type_error(env, nullptr, "Integer expected");
        assert(status == napi_ok);
        return nullptr;
    }
    assert(status == napi_ok);

    status = napi_get_value_int32(env, args[1], &transport);
    if (status == napi_number_expected)
    {
        status = napi_throw_type_error(env, nullptr, "Integer expected");
        assert(status == napi_ok);
        return nullptr;
    }
    assert(status == napi_ok);

    status = napi_get_value_int32(env, args[2], &preset);
    if (status == napi_number_expected)
    {
        status = napi_throw_type_error(env, nullptr, "Integer expected");
        assert(status == napi_ok);
        return nullptr;
    }
    assert(status == napi_ok);

    ret = mbedtls_ssl_config_defaults(self, endpoint, transport, preset);

    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslConfig::Authmode(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    SslConfig* self;
    size_t argc = 1;
    napi_value args[1];
    int authmode;
    napi_value jsret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // Get params: self (this), authmode
    if (argc < 1)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_get_value_int32(env, args[0], &authmode);
    if (status == napi_number_expected)
    {
        status = napi_throw_type_error(env, nullptr, "Integer expected");
        assert(status == napi_ok);
        return nullptr;
    }
    assert(status == napi_ok);

    mbedtls_ssl_conf_authmode(self, authmode);

    status = napi_get_undefined(env, &jsret);
    assert(status == napi_ok);

    return jsret;
}

int SslConfig::RngCb(void *ctx, unsigned char *buf, size_t len)
{
    napi_status status;
    SslConfig *self = reinterpret_cast<SslConfig *>(ctx);
    const int argc = 3;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsres;
    void *data;
    int res;

    // prepare args: context, buffer, length
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_buffer(self->mEnvironment, len, &data, &argv[1]);
    assert(status == napi_ok);

    status = napi_create_int32(self->mEnvironment, len, &argv[2]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mRngCallback, &func);
    assert(status == napi_ok);

    memset(data, 0, len);
    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsres);
    assert(status == napi_ok);

    memcpy(buf, data, len);

    // retrieve return value
    status = napi_get_value_int32(self->mEnvironment, jsres, &res);
    assert(status == napi_ok);

    return res;
}

napi_value SslConfig::Rng(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    SslConfig* self;
    size_t argc = 1;
    napi_value args[argc];
    napi_valuetype type;
    napi_value jsret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), callback
    if (argc < 1)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(env, args[0], &type);
    assert(status == napi_ok);
    if (type == napi_null)
    {
        args[0] = nullptr;
    }
    else if (type != napi_function)
    {
        status = napi_throw_type_error(env, nullptr, "Function expected");
        goto exit;
    }

    // call
    status = rereference(env, self->mRngCallback, args[0]);
    assert(status == napi_ok);

    mbedtls_ssl_conf_rng(self, args[0] ? RngCb : nullptr, self);

exit:
    // return
    status = napi_get_undefined(env, &jsret);
    assert(status == napi_ok);

    return jsret;
}

void SslConfig::DbgCb(void *ctx, int level, const char *file, int line,
        const char *msg)
{
    napi_status status;
    SslConfig *self = reinterpret_cast<SslConfig *>(ctx);
    const int argc = 4;
    napi_value argv[argc];
    napi_value global;
    napi_value func;

    // prepare args: level, file, line, msg
    status = napi_create_int32(self->mEnvironment, level, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_string_utf8(self->mEnvironment, file, NAPI_AUTO_LENGTH, &argv[1]);
    assert(status == napi_ok);

    status = napi_create_int32(self->mEnvironment, line, &argv[2]);
    assert(status == napi_ok);

    status = napi_create_string_utf8(self->mEnvironment, msg, NAPI_AUTO_LENGTH, &argv[3]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mDbgCallback, &func);
    assert(status == napi_ok);

    status = napi_call_function(self->mEnvironment, global, func, argc, argv, nullptr);
    assert(status == napi_ok);
}

napi_value SslConfig::Dbg(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    SslConfig* self;
    size_t argc = 1;
    napi_value args[argc];
    napi_valuetype type;
    napi_value jsret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), callback
    if (argc < 1)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(env, args[0], &type);
    assert(status == napi_ok);
    if (type == napi_null)
    {
        args[0] = nullptr;
    }
    else if (type != napi_function)
    {
        status = napi_throw_type_error(env, nullptr, "Function expected");
        goto exit;
    }

    // call
    status = rereference(env, self->mDbgCallback, args[0]);
    assert(status == napi_ok);

    mbedtls_ssl_conf_dbg(self, args[0] ? DbgCb : nullptr, self);

exit:
    // return
    status = napi_get_undefined(env, &jsret);
    assert(status == napi_ok);

    return jsret;
}

int SslConfig::CookieWriteCb(void *ctx, unsigned char **p, unsigned char *end,
            const unsigned char *info, size_t ilen)
{
    napi_status status;
    SslConfig *self = reinterpret_cast<SslConfig *>(ctx);
    const int argc = 3;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;
    const int32_t max_cookie_len = end - *p;
    void *cookie;
    int ret;

    // prepare args: context, pbuf, info
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_buffer(self->mEnvironment, max_cookie_len, &cookie, &argv[1]);
    assert(status == napi_ok);

    status = napi_create_buffer_copy(self->mEnvironment, ilen, info, nullptr, &argv[2]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mCookieWriteCallback, &func);
    assert(status == napi_ok);

    memset(cookie, 0, max_cookie_len);
    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    assert(status == napi_ok);

    // retrieve return value
    status = napi_get_value_int32(self->mEnvironment, jsret, &ret);
    assert(status == napi_ok);

    if (ret > max_cookie_len)
    {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    else if (ret > 0)
    {
        memcpy(*p, cookie, ret);
        *p += ret;
        ret = 0;
    }

    return ret;
}

int SslConfig::CookieCheckCb(void *ctx, const unsigned char *cookie, size_t clen,
            const unsigned char *info, size_t ilen)
{
    napi_status status;
    SslConfig *self = reinterpret_cast<SslConfig *>(ctx);
    const int argc = 3;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;
    int ret;

    // prepare args: context, pbuf, info
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_buffer_copy(self->mEnvironment, clen, cookie, nullptr, &argv[1]);
    assert(status == napi_ok);

    status = napi_create_buffer_copy(self->mEnvironment, ilen, info, nullptr, &argv[2]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mCookieCheckCallback, &func);
    assert(status == napi_ok);

    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    assert(status == napi_ok);

    // retrieve return value
    status = napi_get_value_int32(self->mEnvironment, jsret, &ret);
    assert(status == napi_ok);

    return ret;
}

napi_value SslConfig::DtlsCookies(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    SslConfig* self;
    size_t argc = 2;
    napi_value args[argc];
    napi_valuetype type;
    napi_value jsret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), write_cb, check_cb
    if (argc < 2)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(env, args[0], &type);
    assert(status == napi_ok);
    if (type == napi_null)
    {
        args[0] = nullptr;
    }
    else if (type != napi_function)
    {
        status = napi_throw_type_error(env, nullptr, "write_callback must be a function");
        goto exit;
    }

    status = napi_typeof(env, args[1], &type);
    assert(status == napi_ok);
    if (type == napi_null)
    {
        args[1] = nullptr;
    }
    else if (type != napi_function)
    {
        status = napi_throw_type_error(env, nullptr, "check_callback must be a function");
        goto exit;
    }

    // call
    status = rereference(env, self->mCookieWriteCallback, args[0]);
    assert(status == napi_ok);

    status = rereference(env, self->mCookieCheckCallback, args[1]);
    assert(status == napi_ok);

    mbedtls_ssl_conf_dtls_cookies(
            self,
            args[0] ? CookieWriteCb : nullptr,
            args[1] ? CookieCheckCb : nullptr,
            self
    );

exit:
    // return
    status = napi_get_undefined(env, &jsret);
    assert(status == napi_ok);

    return jsret;
}

int SslConfig::PskCb(void *ctx, mbedtls_ssl_context *ssl,
            const unsigned char *psk_id, size_t len)
{
    napi_status status;
    SslConfig *self = reinterpret_cast<SslConfig *>(ctx);
    const int argc = 2;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;
    bool is_buffer;
    uint8_t *psk;
    size_t psk_len;

    // prepare args: context, pbuf, info
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_buffer_copy(self->mEnvironment, len, psk_id, nullptr, &argv[1]);
    assert(status == napi_ok);
    // XXX: now sure how to pass in ssl context...
    // so just get a buffer as a return value and call mbedtls_ssl_set_hs_psk natively.

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mPskCallback, &func);
    assert(status == napi_ok);

    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    if (status != napi_ok)
    {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    // retrieve return value
    status = napi_is_buffer(self->mEnvironment, jsret, &is_buffer);
    assert(status == napi_ok);

    if (is_buffer)
    {
        status = napi_get_buffer_info(self->mEnvironment, jsret,
                reinterpret_cast<void **>(&psk), &psk_len);
        assert(status == napi_ok);

        return mbedtls_ssl_set_hs_psk(ssl, psk, psk_len);
    }

    return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
}

napi_value SslConfig::Psk(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 2;
    napi_value args[argc];
    napi_value jsret;
    SslConfig* self;
    napi_valuetype type;
    bool is_buffer;
    uint8_t *psk, *psk_id;
    size_t psk_len, psk_id_len;
    int ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), psk_identity, psk
    if (argc < 2)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(env, args[0], &type);
    assert(status == napi_ok);
    status = napi_is_buffer(env, args[0], &is_buffer);
    assert(status == napi_ok);
    if (type == napi_null)
    {
        psk = nullptr;
        psk_len = 0;
    }
    else if (is_buffer)
    {
        status = napi_get_buffer_info(env, args[0],
                reinterpret_cast<void **>(&psk), &psk_len);
        assert(status == napi_ok);
    }
    else
    {
        status = napi_throw_type_error(env, nullptr, "psk must be a buffer");
        assert(status == napi_ok);
        goto exit;
    }

    status = napi_typeof(env, args[1], &type);
    assert(status == napi_ok);
    status = napi_is_buffer(env, args[1], &is_buffer);
    assert(status == napi_ok);
    if (type == napi_null)
    {
        psk_id = nullptr;
        psk_id_len = 0;
    }
    else if (is_buffer)
    {
        status = napi_get_buffer_info(env, args[1],
                reinterpret_cast<void **>(&psk_id), &psk_id_len);
        assert(status == napi_ok);
    }
    else
    {
        status = napi_throw_type_error(env, nullptr, "psk must be a buffer");
        assert(status == napi_ok);
        goto exit;
    }

    // call
    ret = mbedtls_ssl_conf_psk(self, psk, psk_len, psk_id, psk_id_len);

exit:
    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslConfig::PskCallback(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    SslConfig* self;
    size_t argc = 2;
    napi_value args[2];
    napi_valuetype type;
    napi_value jsret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), psk_cb
    if (argc < 1)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(env, args[0], &type);
    assert(status == napi_ok);
    if (type == napi_null)
    {
        args[0] = nullptr;
    }
    else if (type != napi_function)
    {
        status = napi_throw_type_error(env, nullptr, "psk_callback must be a function");
        goto exit;
    }

    // call
    status = rereference(env, self->mPskCallback, args[0]);
    assert(status == napi_ok);

    mbedtls_ssl_conf_psk_cb(self, args[0] ? PskCb : nullptr, self);

exit:
    // return
    status = napi_get_undefined(env, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslConfig::CaChain(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 2;
    napi_value args[argc];
    SslConfig *self;
    X509Crt *ca_chain;
    X509Crl *ca_crl;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), ca_chain, ca_crl
    if (argc < 2)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = X509Crt::unwrap(env, args[0], &ca_chain);
    if (status == napi_invalid_arg)
    {
        status = napi_throw_type_error(env, nullptr, "Expected mbedtls_x509_crt");
        return nullptr;
    }
    assert(status == napi_ok);

    status = X509Crl::unwrap(env, args[1], &ca_crl);
    if (status == napi_invalid_arg)
    {
        status = napi_throw_type_error(env, nullptr, "Expected mbedtls_x509_crl");
        return nullptr;
    }
    assert(status == napi_ok);

    // call
    mbedtls_ssl_conf_ca_chain(self, ca_chain, ca_crl);

    // return
    return nullptr;
}

napi_value SslConfig::OwnCert(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 2;
    napi_value args[argc];
    napi_value jsret;
    SslConfig *self;
    X509Crt *own_cert;
    PKContext *pk_key;
    int ret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), own_cert, pk_key
    if (argc < 2)
    {
        status = napi_throw_type_error(env, nullptr, "Missing arguments");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = X509Crt::unwrap(env, args[0], &own_cert);
    if (status == napi_invalid_arg)
    {
        status = napi_throw_type_error(env, nullptr, "Expected mbedtls_x509_crt");
        return nullptr;
    }
    assert(status == napi_ok);

    status = PKContext::unwrap(env, args[1], &pk_key);
    if (status == napi_invalid_arg)
    {
        status = napi_throw_type_error(env, nullptr, "Expected mbedtls_pk_context");
        return nullptr;
    }
    assert(status == napi_ok);

    // call
    ret = mbedtls_ssl_conf_own_cert(self, own_cert, pk_key);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}
