#include <oqs/oqs.h>
#include <stddef.h>
#include <stdint.h>

#define NOCTWEAVE_OK 0
#define NOCTWEAVE_ERR_INVALID_ARGUMENT -1
#define NOCTWEAVE_ERR_UNAVAILABLE -2
#define NOCTWEAVE_ERR_CRYPTO -3

static OQS_KEM *noctweave_kem = NULL;
static OQS_SIG *noctweave_sig = NULL;

static int noctweave_require_init(void) {
    if (noctweave_kem != NULL && noctweave_sig != NULL) {
        return NOCTWEAVE_OK;
    }

    OQS_init();

    noctweave_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    noctweave_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (noctweave_kem == NULL || noctweave_sig == NULL) {
        if (noctweave_kem != NULL) {
            OQS_KEM_free(noctweave_kem);
            noctweave_kem = NULL;
        }
        if (noctweave_sig != NULL) {
            OQS_SIG_free(noctweave_sig);
            noctweave_sig = NULL;
        }
        return NOCTWEAVE_ERR_UNAVAILABLE;
    }

    return NOCTWEAVE_OK;
}

int noctweave_oqs_init(void) {
    return noctweave_require_init();
}

const char *noctweave_oqs_profile_json(void) {
    return "{\"kem\":{\"algorithm\":\"ML-KEM-768\",\"publicKeyLength\":1184,\"secretKeyLength\":2400,\"ciphertextLength\":1088,\"sharedSecretLength\":32},\"signature\":{\"algorithm\":\"ML-DSA-65\",\"publicKeyLength\":1952,\"secretKeyLength\":4032,\"signatureLength\":3309}}";
}

int noctweave_kem_public_key_length(void) {
    return OQS_KEM_ml_kem_768_length_public_key;
}

int noctweave_kem_secret_key_length(void) {
    return OQS_KEM_ml_kem_768_length_secret_key;
}

int noctweave_kem_ciphertext_length(void) {
    return OQS_KEM_ml_kem_768_length_ciphertext;
}

int noctweave_kem_shared_secret_length(void) {
    return OQS_KEM_ml_kem_768_length_shared_secret;
}

int noctweave_sig_public_key_length(void) {
    return OQS_SIG_ml_dsa_65_length_public_key;
}

int noctweave_sig_secret_key_length(void) {
    return OQS_SIG_ml_dsa_65_length_secret_key;
}

int noctweave_sig_signature_length(void) {
    return OQS_SIG_ml_dsa_65_length_signature;
}

int noctweave_kem_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (public_key == NULL || secret_key == NULL) {
        return NOCTWEAVE_ERR_INVALID_ARGUMENT;
    }
    if (noctweave_require_init() != NOCTWEAVE_OK) {
        return NOCTWEAVE_ERR_UNAVAILABLE;
    }
    return OQS_KEM_keypair(noctweave_kem, public_key, secret_key) == OQS_SUCCESS
        ? NOCTWEAVE_OK
        : NOCTWEAVE_ERR_CRYPTO;
}

int noctweave_kem_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key,
    size_t public_key_len
) {
    if (
        ciphertext == NULL ||
        shared_secret == NULL ||
        public_key == NULL ||
        public_key_len != OQS_KEM_ml_kem_768_length_public_key
    ) {
        return NOCTWEAVE_ERR_INVALID_ARGUMENT;
    }
    if (noctweave_require_init() != NOCTWEAVE_OK) {
        return NOCTWEAVE_ERR_UNAVAILABLE;
    }
    return OQS_KEM_encaps(noctweave_kem, ciphertext, shared_secret, public_key) == OQS_SUCCESS
        ? NOCTWEAVE_OK
        : NOCTWEAVE_ERR_CRYPTO;
}

int noctweave_kem_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *secret_key,
    size_t secret_key_len
) {
    if (
        shared_secret == NULL ||
        ciphertext == NULL ||
        secret_key == NULL ||
        ciphertext_len != OQS_KEM_ml_kem_768_length_ciphertext ||
        secret_key_len != OQS_KEM_ml_kem_768_length_secret_key
    ) {
        return NOCTWEAVE_ERR_INVALID_ARGUMENT;
    }
    if (noctweave_require_init() != NOCTWEAVE_OK) {
        return NOCTWEAVE_ERR_UNAVAILABLE;
    }
    return OQS_KEM_decaps(noctweave_kem, shared_secret, ciphertext, secret_key) == OQS_SUCCESS
        ? NOCTWEAVE_OK
        : NOCTWEAVE_ERR_CRYPTO;
}

int noctweave_sig_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (public_key == NULL || secret_key == NULL) {
        return NOCTWEAVE_ERR_INVALID_ARGUMENT;
    }
    if (noctweave_require_init() != NOCTWEAVE_OK) {
        return NOCTWEAVE_ERR_UNAVAILABLE;
    }
    return OQS_SIG_keypair(noctweave_sig, public_key, secret_key) == OQS_SUCCESS
        ? NOCTWEAVE_OK
        : NOCTWEAVE_ERR_CRYPTO;
}

int noctweave_sig_sign(
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key,
    size_t secret_key_len
) {
    if (
        signature == NULL ||
        signature_len == NULL ||
        message == NULL ||
        secret_key == NULL ||
        secret_key_len != OQS_SIG_ml_dsa_65_length_secret_key
    ) {
        return NOCTWEAVE_ERR_INVALID_ARGUMENT;
    }
    if (noctweave_require_init() != NOCTWEAVE_OK) {
        return NOCTWEAVE_ERR_UNAVAILABLE;
    }
    return OQS_SIG_sign(noctweave_sig, signature, signature_len, message, message_len, secret_key) == OQS_SUCCESS
        ? NOCTWEAVE_OK
        : NOCTWEAVE_ERR_CRYPTO;
}

int noctweave_sig_verify(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *public_key,
    size_t public_key_len
) {
    if (
        message == NULL ||
        signature == NULL ||
        public_key == NULL ||
        public_key_len != OQS_SIG_ml_dsa_65_length_public_key
    ) {
        return NOCTWEAVE_ERR_INVALID_ARGUMENT;
    }
    if (noctweave_require_init() != NOCTWEAVE_OK) {
        return NOCTWEAVE_ERR_UNAVAILABLE;
    }
    return OQS_SIG_verify(noctweave_sig, message, message_len, signature, signature_len, public_key) == OQS_SUCCESS
        ? NOCTWEAVE_OK
        : NOCTWEAVE_ERR_CRYPTO;
}

void noctweave_memzero(uint8_t *ptr, size_t len) {
    if (ptr == NULL) {
        return;
    }
    volatile uint8_t *volatile_ptr = ptr;
    while (len > 0) {
        *volatile_ptr++ = 0;
        len--;
    }
}
