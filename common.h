#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hpke.h>

#define PIPE_toReceiver "toReceiver"
#define PIPE_toSender   "toSender"

#define INFO_TXT "info"
#define AAD_TXT  "aad"

#define KEM  DHKEM_X25519_HKDF_SHA256
/*
    DHKEM_P256_HKDF_SHA256
    DHKEM_P384_HKDF_SHA384
    DHKEM_P521_HKDF_SHA512
    DHKEM_X25519_HKDF_SHA256
*/

#define KDF  HKDF_SHA256
/*
    HKDF_SHA256
    HKDF_SHA384
    HKDF_SHA512
*/

#define AEAD HPKE_AES_256_GCM
/*
    HPKE_AES_128_GCM,
    HPKE_AES_256_GCM,
*/