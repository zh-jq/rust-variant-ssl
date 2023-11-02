#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>

#define VERSION2(n, v) RUST_VERSION_##n##_##v
#define VERSION(n, v) VERSION2(n, v)

#define NEW_VERSION2(a, b, c) RUST_VERSION_NEW_OPENSSL_##a##_##b##_##c
#define NEW_VERSION(a, b, c) NEW_VERSION2(a, b, c)

#ifdef LIBRESSL_VERSION_NUMBER
VERSION(LIBRESSL, LIBRESSL_VERSION_NUMBER)
#elif defined OPENSSL_VERSION_MAJOR
NEW_VERSION(OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR, OPENSSL_VERSION_PATCH)
#else
VERSION(OPENSSL, OPENSSL_VERSION_NUMBER)
#endif

#ifdef OPENSSL_IS_BORINGSSL
RUST_OPENSSL_IS_BORINGSSL
#endif

#ifdef TONGSUO_VERSION_NUMBER
RUST_OPENSSL_IS_TONGSUO
#endif

#ifdef OPENSSL_NO_BF
RUST_CONF_OPENSSL_NO_BF
#endif

#ifdef OPENSSL_NO_BUF_FREELISTS
RUST_CONF_OPENSSL_NO_BUF_FREELISTS
#endif

#ifdef OPENSSL_NO_CHACHA
RUST_CONF_OPENSSL_NO_CHACHA
#endif

#ifdef OPENSSL_NO_IDEA
RUST_CONF_OPENSSL_NO_IDEA
#endif

#ifdef OPENSSL_NO_CAMELLIA
RUST_CONF_OPENSSL_NO_CAMELLIA
#endif

#ifdef OPENSSL_NO_CAST
RUST_CONF_OPENSSL_NO_CAST
#endif

#ifdef OPENSSL_NO_CMS
RUST_CONF_OPENSSL_NO_CMS
#endif

#ifdef OPENSSL_NO_COMP
RUST_CONF_OPENSSL_NO_COMP
#endif

#ifdef OPENSSL_NO_EC
RUST_CONF_OPENSSL_NO_EC
#endif

#ifdef OPENSSL_NO_EC2M
RUST_CONF_OPENSSL_NO_EC2M
#endif

#ifdef OPENSSL_NO_ENGINE
RUST_CONF_OPENSSL_NO_ENGINE
#endif

#ifdef OPENSSL_NO_KRB5
RUST_CONF_OPENSSL_NO_KRB5
#endif

#ifdef OPENSSL_NO_NEXTPROTONEG
RUST_CONF_OPENSSL_NO_NEXTPROTONEG
#endif

#ifdef OPENSSL_NO_OCSP
RUST_CONF_OPENSSL_NO_OCSP
#endif

#ifdef OPENSSL_NO_OCB
RUST_CONF_OPENSSL_NO_OCB
#endif

#ifdef OPENSSL_NO_PSK
RUST_CONF_OPENSSL_NO_PSK
#endif

#ifdef OPENSSL_NO_RC4
RUST_CONF_OPENSSL_NO_RC4
#endif

#ifdef OPENSSL_NO_RFC3779
RUST_CONF_OPENSSL_NO_RFC3779
#endif

#ifdef OPENSSL_NO_RMD160
RUST_CONF_OPENSSL_NO_RMD160
#endif

#ifdef OPENSSL_NO_SHA
RUST_CONF_OPENSSL_NO_SHA
#endif

#ifdef OPENSSL_NO_SRP
RUST_CONF_OPENSSL_NO_SRP
#endif

#ifdef OPENSSL_NO_SSL3_METHOD
RUST_CONF_OPENSSL_NO_SSL3_METHOD
#endif

#ifdef OPENSSL_NO_TLSEXT
RUST_CONF_OPENSSL_NO_TLSEXT
#endif

#ifdef OPENSSL_NO_SOCK
RUST_CONF_OPENSSL_NO_SOCK
#endif

#ifdef OPENSSL_NO_STDIO
RUST_CONF_OPENSSL_NO_STDIO
#endif

#ifdef OPENSSL_NO_SM3
RUST_CONF_OPENSSL_NO_SM3
#endif

#ifdef OPENSSL_NO_SM4
RUST_CONF_OPENSSL_NO_SM4
#endif

#ifdef OPENSSL_NO_DEPRECATED_3_0
RUST_CONF_OPENSSL_NO_DEPRECATED_3_0
#endif

#ifdef OPENSSL_NO_SEED
RUST_CONF_OPENSSL_NO_SEED
#endif

#ifdef OPENSSL_NO_SCRYPT
RUST_CONF_OPENSSL_NO_SCRYPT
#endif
