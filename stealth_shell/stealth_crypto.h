#ifndef STEALTH_CRYPTO_H
#define STEALTH_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define CRYPTO_IV_SIZE    16
#define CRYPTO_HMAC_SIZE  32
#define CRYPTO_KEY_SIZE   32

int stealth_encrypt(const uint8_t *plaintext, uint16_t len,
                    uint8_t *iv_out,
                    uint8_t *ciphertext,
                    uint8_t *hmac_out);

int stealth_decrypt(const uint8_t *ciphertext, uint16_t len,
                    const uint8_t *iv,
                    const uint8_t *hmac,
                    uint8_t *plaintext);

#endif
