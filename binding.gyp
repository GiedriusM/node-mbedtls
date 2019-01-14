{
  "targets": [
    {
      "target_name": "mbedtls",
      "include_dirs": [ "./third_party/mbedtls/include/" ],
      "sources": [
          "mbedtls.cc",
          "ssl_constants.cpp",
          "ssl_config.cpp",
          "ssl_context.cpp"
      ],
      "libraries": [ 
          "./mbedtls/library/libmbedtls.a",
          "./mbedtls/library/libmbedx509.a",
          "./mbedtls/library/libmbedcrypto.a"
      ],
      "cflags": [ "-Wl,--no-undefined" ]
    }
  ]
}
