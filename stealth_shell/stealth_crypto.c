#include "stealth_crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#define PSK_ENC  "stlh_enc_k32_0123456789abcdefXX"
#define PSK_MAC  "stlh_mac_k32_fedcba9876543210XX"

static const uint8_t ENC_KEY[CRYPTO_KEY_SIZE] = PSK_ENC;
static const uint8_t MAC_KEY[CRYPTO_KEY_SIZE] = PSK_MAC;

static int compute_hmac(const uint8_t *iv, const uint8_t *ct, uint16_t ct_len,
                        uint8_t *hmac_out)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) return 0;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); return 0; }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    int ok = 1;
    if (!EVP_MAC_init(ctx, MAC_KEY, CRYPTO_KEY_SIZE, params)) { ok = 0; goto done; }
    if (!EVP_MAC_update(ctx, iv, CRYPTO_IV_SIZE))              { ok = 0; goto done; }
    if (!EVP_MAC_update(ctx, ct, ct_len))                      { ok = 0; goto done; }
    size_t hlen = CRYPTO_HMAC_SIZE;
    if (!EVP_MAC_final(ctx, hmac_out, &hlen, CRYPTO_HMAC_SIZE)) ok = 0;
done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

int stealth_encrypt(const uint8_t *plaintext, uint16_t len,
                    uint8_t *iv_out, uint8_t *ciphertext, uint8_t *hmac_out)
{
    if (RAND_bytes(iv_out, CRYPTO_IV_SIZE) != 1) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int ok = 1, out_len = 0, final_len = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, ENC_KEY, iv_out))
        { ok = 0; goto done; }
    if (!EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, (int)len))
        { ok = 0; goto done; }
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len))
        { ok = 0; }
done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;
    return compute_hmac(iv_out, ciphertext, len, hmac_out);
}

int stealth_decrypt(const uint8_t *ciphertext, uint16_t len,
                    const uint8_t *iv, const uint8_t *hmac, uint8_t *plaintext)
{
    uint8_t expected[CRYPTO_HMAC_SIZE];
    if (!compute_hmac(iv, ciphertext, len, expected)) return 0;
    if (CRYPTO_memcmp(expected, hmac, CRYPTO_HMAC_SIZE) != 0) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int ok = 1, out_len = 0, final_len = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, ENC_KEY, iv))
        { ok = 0; goto done; }
    if (!EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, (int)len))
        { ok = 0; goto done; }
    if (!EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len))
        { ok = 0; }
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
