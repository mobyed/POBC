#ifndef AES_MODES_H
#define AES_MODES_H

#include "../aes/aes.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

void aes_ctr_dec(uint8_t *output, const uint8_t *counter, const uint8_t *ciphertext, size_t ciphertext_len, const rkey_t *rkeys);
void pmac(uint8_t *tag, const uint8_t *message_blocks, size_t num_blocks, const rkey_t *rkeys);
void digest(uint8_t *hash, const uint8_t *blocks, size_t num_blocks, const uint8_t *nonce);
void enc_pmac_aes128(uint8_t *ciphertext, uint8_t *tag, const uint8_t *message, size_t message_len, const uint8_t *key, const uint8_t *nonce);
bool dec_pmac_aes128(uint8_t *message, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag, const uint8_t *key, const uint8_t *nonce);
void enc_htmac_aes128(uint8_t *ciphertext, uint8_t *tag, const uint8_t *message, size_t message_len, const uint8_t *key, const uint8_t *nonce);
bool dec_htmac_aes128(uint8_t *message, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag, const uint8_t *key, const uint8_t *nonce);
void gf128_double(uint8_t *result, const uint8_t *input);
void xor_blocks(uint8_t *result, const uint8_t *a, const uint8_t *b);
bool tag_compare(const uint8_t *tag1, const uint8_t *tag2);

#endif