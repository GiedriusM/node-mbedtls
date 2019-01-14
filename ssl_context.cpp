#include "ssl_context.hpp"

#include <assert.h>
#include <string.h>

#include "ssl_config.hpp"
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

napi_ref SslContext::sConstructor;

napi_value SslContext::Init(napi_env env, napi_value exports)
{
    napi_status status;
    const size_t num_properties = 10;
    napi_property_descriptor properties[num_properties] = {
        DECLARE_NAPI_PROPERTY("state", GetState, nullptr),
        DECLARE_NAPI_METHOD("setup", Setup),
        DECLARE_NAPI_METHOD("set_bio", SetBio),
        DECLARE_NAPI_METHOD("set_timer_cb", SetTimerCallback),
        DECLARE_NAPI_METHOD("session_reset", SessionReset),
        DECLARE_NAPI_METHOD("handshake", Handshake),
        DECLARE_NAPI_METHOD("read", Read),
        DECLARE_NAPI_METHOD("write", Write),
        DECLARE_NAPI_METHOD("send_alert_message", SendAlertMessage),
        DECLARE_NAPI_METHOD("close_notify", CloseNotify),
    };
    napi_value cons;

    status = napi_define_class(env, "mbedtls_ssl_context", NAPI_AUTO_LENGTH,
                               New, nullptr, num_properties, properties, &cons);
    assert(status == napi_ok);

    status = napi_create_reference(env, cons, 1, &sConstructor);
    assert(status == napi_ok);

    status = napi_set_named_property(env, exports, "SSLContext", cons);
    assert(status == napi_ok);

    return exports;
}

napi_value SslContext::New(napi_env env, napi_callback_info info)
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

        SslContext *obj = new SslContext(env);

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

void SslContext::Finalize(napi_env env, void *nativeObject, void *finalize_hint)
{
    delete reinterpret_cast<SslContext *>(nativeObject);
}

napi_value SslContext::GetState(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    napi_value jsret;
    SslContext* self;

    status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this)
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    // return state
    status = napi_create_int32(env, self->state, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslContext::Setup(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 1;
    napi_value args[1];
    napi_value jsret;
    SslContext* self;
    SslConfig* config;
    int ret = -1;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), config
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = SslConfig::unwrap(env, args[0], &config);
    assert(status == napi_ok);
    if (config == nullptr)
    {
        status = napi_throw_type_error(env, nullptr, "parameter must be ssl_config");
        goto exit;
    }

    // call
    ret = mbedtls_ssl_setup(self, config);

exit:
    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

int SslContext::BioSendCb(void *ctx, const uint8_t *buf, size_t len)
{
    napi_status status;
    SslContext *self = reinterpret_cast<SslContext *>(ctx);
    const int argc = 2;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;
    int ret;

    // prepare args: context, buffer
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_buffer_copy(self->mEnvironment, len, buf, nullptr, &argv[1]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mBioSendCallback, &func);
    assert(status == napi_ok);

    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    if (status != napi_ok)
    {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    // retrieve return value
    status = napi_get_value_int32(self->mEnvironment, jsret, &ret);
    assert(status == napi_ok);

    return ret;
}

int SslContext::BioRecvCb(void *ctx, uint8_t *buf, size_t len)
{
    assert(false);
}

int SslContext::BioRecvTimeoutCb(void *ctx, uint8_t *buf, size_t len, uint32_t timeout)
{
    napi_status status;
    SslContext *self = reinterpret_cast<SslContext *>(ctx);
    const int argc = 3;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;
    void *data;
    int ret;

    // prepare args: context, buffer, timeout
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_buffer(self->mEnvironment, len, &data, &argv[1]);
    assert(status == napi_ok);

    status = napi_create_int32(self->mEnvironment, timeout, &argv[2]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mBioRecvTimeoutCallback, &func);
    assert(status == napi_ok);

    memset(data, 0, len);
    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    if (status != napi_ok)
    {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    // retrieve return value
    status = napi_get_value_int32(self->mEnvironment, jsret, &ret);
    if (status != napi_ok)
    {
        // XXX: should it be internal error, WANT_READ or something else?
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    memcpy(buf, data, len);

    return ret;
}

napi_value SslContext::SetBio(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 4;
    napi_value args[4];
    napi_valuetype type;
    napi_value jsret;
    SslContext *self;
    decltype(BioSendCb) *send_cb = nullptr;
    decltype(BioRecvCb) *recv_cb = nullptr;
    decltype(BioRecvTimeoutCb) *recv_timeout_cb = nullptr;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), context, bio_send, bio_receive, bio_receive_timeout
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(env, args[1], &type);
    assert(status == napi_ok);
    if (type == napi_function)
    {
        send_cb = BioSendCb;
    }
    else
    {
        status = napi_throw_type_error(env, nullptr, "bio_send must be a function");
        goto exit;
    }

    status = napi_typeof(env, args[2], &type);
    assert(status == napi_ok);
    if (type == napi_function)
    {
        recv_cb = BioRecvCb;
    }
    else if (type != napi_null)
    {
        status = napi_throw_type_error(env, nullptr, "bio_recv must be a function");
        goto exit;
    }

    status = napi_typeof(env, args[3], &type);
    assert(status == napi_ok);
    if (type == napi_function)
    {
        recv_timeout_cb = BioRecvTimeoutCb;
    }
    else if (type != napi_null)
    {
        status = napi_throw_type_error(env, nullptr, "bio_recv_timeout must be a function");
        goto exit;
    }

    if (recv_cb == nullptr && recv_timeout_cb == nullptr)
    {
        status = napi_throw_type_error(env, nullptr, "bio_recv or bio_recv_timeout must be non-null");
        goto exit;
    }

    // call
    status = rereference(env, self->mBioSendCallback, args[1]);
    assert(status == napi_ok);

    status = rereference(env, self->mBioRecvCallback, recv_cb ? args[2] : nullptr);
    assert(status == napi_ok);

    status = rereference(env, self->mBioRecvTimeoutCallback,
            recv_timeout_cb ? args[3] : nullptr);
    assert(status == napi_ok);

    mbedtls_ssl_set_bio(self, self, send_cb, recv_cb, recv_timeout_cb);

exit:
    // return
    status = napi_get_undefined(env, &jsret);
    assert(status == napi_ok);

    return jsret;
}

void SslContext::TimerSetCallback(void *ctx, uint32_t int_ms, uint32_t fin_ms)
{
    napi_status status;
    SslContext *self = reinterpret_cast<SslContext *>(ctx);
    const int argc = 3;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;

    // prepare args: context, int_ms, fin_ms
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    status = napi_create_int32(self->mEnvironment, int_ms, &argv[1]);
    assert(status == napi_ok);

    status = napi_create_int32(self->mEnvironment, fin_ms, &argv[2]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mTimerSetCallback, &func);
    assert(status == napi_ok);

    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    assert(status == napi_ok);
}

int SslContext::TimerGetCallback(void *ctx)
{
    napi_status status;
    SslContext *self = reinterpret_cast<SslContext *>(ctx);
    const int argc = 1;
    napi_value argv[argc];
    napi_value global;
    napi_value func;
    napi_value jsret;
    int ret;

    // prepare args: context
    status = napi_create_int32(self->mEnvironment, 0, &argv[0]);
    assert(status == napi_ok);

    // call function
    status = napi_get_global(self->mEnvironment, &global);
    assert(status == napi_ok);

    status = napi_get_reference_value(self->mEnvironment, self->mTimerGetCallback, &func);
    assert(status == napi_ok);

    status = napi_call_function(self->mEnvironment, global, func, argc, argv, &jsret);
    assert(status == napi_ok);

    // retrieve return value
    status = napi_get_value_int32(self->mEnvironment, jsret, &ret);
    assert(status == napi_ok);

    return ret;
}

napi_value SslContext::SetTimerCallback(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 4;
    napi_value args[4];
    napi_valuetype type;
    napi_value jsret;
    SslContext *self;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), context, set_timer_cb, get_timer_cb
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_typeof(env, args[1], &type);
    assert(status == napi_ok);
    if (type != napi_function)
    {
        status = napi_throw_type_error(env, nullptr, "set_timer must be a function");
        goto exit;
    }

    status = napi_typeof(env, args[2], &type);
    assert(status == napi_ok);
    if (type != napi_function)
    {
        status = napi_throw_type_error(env, nullptr, "get_timer must be a function");
        goto exit;
    }

    // call
    status = rereference(env, self->mTimerSetCallback, args[1]);
    assert(status == napi_ok);

    status = rereference(env, self->mTimerGetCallback, args[2]);
    assert(status == napi_ok);

    mbedtls_ssl_set_timer_cb(self, self, TimerSetCallback, TimerGetCallback);

exit:
    // return
    status = napi_get_undefined(env, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslContext::SessionReset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    napi_value jsret;
    SslContext *self;
    int ret;

    status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this)
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    // call
    ret = mbedtls_ssl_session_reset(self);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslContext::Handshake(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    napi_value jsret;
    SslContext *self;
    int ret;

    status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this)
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    // call
    ret = mbedtls_ssl_handshake(self);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslContext::Read(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 1;
    napi_value args[argc];
    napi_value jsret;
    SslContext *self;
    uint8_t *buffer;
    size_t length;
    int ret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), buffer, length
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_get_buffer_info(env, args[0], reinterpret_cast<void **>(&buffer), &length);
    assert(status == napi_ok);

    // call
    ret = mbedtls_ssl_read(self, buffer, length);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslContext::Write(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 1;
    napi_value args[argc];
    napi_value jsret;
    SslContext *self;
    bool is_buf;
    uint8_t *buf;
    size_t len;
    int ret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), buffer, length
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_is_buffer(env, args[0], &is_buf);
    assert(status == napi_ok);
    if (!is_buf)
    {
        status = napi_throw_type_error(env, nullptr, "argument is not a buffer");
        assert(status == napi_ok);
        return nullptr;
    }

    status = napi_get_buffer_info(env, args[0], reinterpret_cast<void **>(&buf), &len);
    assert(status == napi_ok);

    // call
    ret = mbedtls_ssl_write(self, buf, len);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslContext::SendAlertMessage(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    size_t argc = 2;
    napi_value args[argc];
    napi_value jsret;
    SslContext *self;
    int lvl, msg;
    int ret;

    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this), level, message
    assert(argc == 2);

    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    status = napi_get_value_int32(env, args[0], &lvl);
    assert(status == napi_ok);

    status = napi_get_value_int32(env, args[1], &msg);
    assert(status == napi_ok);

    // call
    ret = mbedtls_ssl_send_alert_message(self, lvl, msg);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}

napi_value SslContext::CloseNotify(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsthis;
    napi_value jsret;
    SslContext *self;
    int ret;

    status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
    assert(status == napi_ok);

    // get params: self (this)
    status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&self));
    assert(status == napi_ok);

    // call
    ret = mbedtls_ssl_close_notify(self);

    // return
    status = napi_create_int32(env, ret, &jsret);
    assert(status == napi_ok);

    return jsret;
}
