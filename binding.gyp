{
  "target_defaults": {
    "include_dirs": [
      "./third_party/mbedtls/include/",
      "./configs/"
    ],
    "defines": [
      "MBEDTLS_CONFIG_FILE=\"node-mbedtls-config.h\""
    ]
  },
  "targets": [
    {
      "target_name": "libmbedcrypto",
      "type": "static_library",
      "sources": [
        "./third_party/mbedtls/library/aes.c",
        "./third_party/mbedtls/library/aesni.c",
        "./third_party/mbedtls/library/arc4.c",
        "./third_party/mbedtls/library/aria.c",
        "./third_party/mbedtls/library/asn1parse.c",
        "./third_party/mbedtls/library/asn1write.c",
        "./third_party/mbedtls/library/base64.c",
        "./third_party/mbedtls/library/bignum.c",
        "./third_party/mbedtls/library/blowfish.c",
        "./third_party/mbedtls/library/camellia.c",
        "./third_party/mbedtls/library/ccm.c",
        "./third_party/mbedtls/library/chacha20.c",
        "./third_party/mbedtls/library/chachapoly.c",
        "./third_party/mbedtls/library/cipher.c",
        "./third_party/mbedtls/library/cipher_wrap.c",
        "./third_party/mbedtls/library/cmac.c",
        "./third_party/mbedtls/library/ctr_drbg.c",
        "./third_party/mbedtls/library/des.c",
        "./third_party/mbedtls/library/dhm.c",
        "./third_party/mbedtls/library/ecdh.c",
        "./third_party/mbedtls/library/ecdsa.c",
        "./third_party/mbedtls/library/ecjpake.c",
        "./third_party/mbedtls/library/ecp.c",
        "./third_party/mbedtls/library/ecp_curves.c",
        "./third_party/mbedtls/library/entropy.c",
        "./third_party/mbedtls/library/entropy_poll.c",
        "./third_party/mbedtls/library/error.c",
        "./third_party/mbedtls/library/gcm.c",
        "./third_party/mbedtls/library/havege.c",
        "./third_party/mbedtls/library/hkdf.c",
        "./third_party/mbedtls/library/hmac_drbg.c",
        "./third_party/mbedtls/library/md.c",
        "./third_party/mbedtls/library/md2.c",
        "./third_party/mbedtls/library/md4.c",
        "./third_party/mbedtls/library/md5.c",
        "./third_party/mbedtls/library/md_wrap.c",
        "./third_party/mbedtls/library/memory_buffer_alloc.c",
        "./third_party/mbedtls/library/nist_kw.c",
        "./third_party/mbedtls/library/oid.c",
        "./third_party/mbedtls/library/padlock.c",
        "./third_party/mbedtls/library/pem.c",
        "./third_party/mbedtls/library/pk.c",
        "./third_party/mbedtls/library/pk_wrap.c",
        "./third_party/mbedtls/library/pkcs12.c",
        "./third_party/mbedtls/library/pkcs5.c",
        "./third_party/mbedtls/library/pkparse.c",
        "./third_party/mbedtls/library/pkwrite.c",
        "./third_party/mbedtls/library/platform.c",
        "./third_party/mbedtls/library/platform_util.c",
        "./third_party/mbedtls/library/poly1305.c",
        "./third_party/mbedtls/library/ripemd160.c",
        "./third_party/mbedtls/library/rsa.c",
        "./third_party/mbedtls/library/rsa_internal.c",
        "./third_party/mbedtls/library/sha1.c",
        "./third_party/mbedtls/library/sha256.c",
        "./third_party/mbedtls/library/sha512.c",
        "./third_party/mbedtls/library/threading.c",
        "./third_party/mbedtls/library/timing.c",
        "./third_party/mbedtls/library/version.c",
        "./third_party/mbedtls/library/version_features.c",
        "./third_party/mbedtls/library/xtea.c",
      ]
    },
    {
      "target_name": "libmbedx509",
      "type": "static_library",
      "dependencies": [ "libmbedcrypto" ],
      "sources": [
        "./third_party/mbedtls/library/certs.c",
        "./third_party/mbedtls/library/pkcs11.c",
        "./third_party/mbedtls/library/x509.c",
        "./third_party/mbedtls/library/x509_create.c",
        "./third_party/mbedtls/library/x509_crl.c",
        "./third_party/mbedtls/library/x509_crt.c",
        "./third_party/mbedtls/library/x509_csr.c",
        "./third_party/mbedtls/library/x509write_crt.c",
        "./third_party/mbedtls/library/x509write_csr.c",
      ]
    },
    {
      "target_name": "libmbedtls",
      "type": "static_library",
      "dependencies": [ "libmbedcrypto", "libmbedx509" ],
      "sources": [
        "./third_party/mbedtls/library/debug.c",
        "./third_party/mbedtls/library/net_sockets.c",
        "./third_party/mbedtls/library/ssl_cache.c",
        "./third_party/mbedtls/library/ssl_ciphersuites.c",
        "./third_party/mbedtls/library/ssl_cli.c",
        "./third_party/mbedtls/library/ssl_cookie.c",
        "./third_party/mbedtls/library/ssl_srv.c",
        "./third_party/mbedtls/library/ssl_ticket.c",
        "./third_party/mbedtls/library/ssl_tls.c",
      ]
    },
    {
      "target_name": "mbedtls",
      "cflags": [ "-Wl,--no-undefined" ],
      "dependencies": [ "libmbedtls" ],
      "conditions": [
        [ '$(NODE_MBEDTLS_COVERAGE)', {
            "cflags": [ "-fprofile-arcs", "-ftest-coverage" ],
            "ldflags": [ "-fprofile-arcs", "-ftest-coverage" ],
          },
        ],
      ],
      "sources": [
          "mbedtls.cc",
          "ssl_constants.cpp",
          "ssl_config.cpp",
          "ssl_context.cpp",
          "x509_crt.cpp",
          "x509_crl.cpp",
          "pk_context.cpp"
      ]
    }
  ]
}
