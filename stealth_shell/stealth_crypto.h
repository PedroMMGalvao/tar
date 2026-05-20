/**
 * @file stealth_crypto.h
 * @brief Módulo criptográfico focado em cifragem simétrica e integridade de dados.
 * @author Pedro Galvão
 * @date 2026
 */

#ifndef STEALTH_CRYPTO_H
#define STEALTH_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define CRYPTO_IV_SIZE    16  /**< Dimensão em bytes necessária para o IV AES-256-CTR */
#define CRYPTO_HMAC_SIZE  32  /**< Dimensão em bytes da assinatura gerada por HMAC-SHA256 */
#define CRYPTO_KEY_SIZE   32  /**< Tamanho de chave estipulado em 256 bits (32 bytes) */

/**
 * @brief Encripta o plaintext usando AES-256-CTR e calcula a respetiva tag HMAC-SHA256.
 * @param plaintext Ponteiro para os dados em texto limpo.
 * @param len Comprimento do plaintext em bytes.
 * @param iv_out Buffer de saída onde o IV aleatório gerado será armazenado.
 * @param ciphertext Buffer de saída para guardar os dados cifrados resultantes.
 * @param hmac_out Buffer de saída para guardar a assinatura digital HMAC.
 * @return 1 se a operação foi bem-sucedida, 0 se ocorreu falha na cifragem ou entropia.
 */
int stealth_encrypt(const uint8_t *plaintext, uint16_t len,
                    uint8_t *iv_out,
                    uint8_t *ciphertext,
                    uint8_t *hmac_out);

/**
 * @brief Valida a tag HMAC e, se fidedigna, desencripta o conteúdo cifrado.
 * @param ciphertext Ponteiro para a sequência de dados em formato cifrado.
 * @param len Comprimento do bloco cifrado em bytes.
 * @param iv Ponteiro para o Vetor de Inicialização usado na cifragem.
 * @param hmac Ponteiro para a assinatura recebida a ser auditada.
 * @param plaintext Buffer de saída onde o texto original decifrado será escrito.
 * @return 1 se o HMAC for autêntico e a decifragem concluir, 0 se o pacote for corrompido/adulterado.
 */
int stealth_decrypt(const uint8_t *ciphertext, uint16_t len,
                    const uint8_t *iv,
                    const uint8_t *hmac,
                    uint8_t *plaintext);

#endif /* STEALTH_CRYPTO_H */