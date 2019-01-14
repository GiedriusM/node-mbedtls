
#define DECLARE_NAPI_METHOD(name, func)                     \
      { name, 0, func, 0, 0, 0, napi_default, 0 }

#define DECLARE_NAPI_PROPERTY(name, getter, setter)         \
      { name, 0, 0, getter, setter, 0, napi_default, 0 }

