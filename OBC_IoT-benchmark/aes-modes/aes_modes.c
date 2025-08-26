#include "aes_modes.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mbedtls/md.h"


void xor_blocks(uint8_t *result, const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 16; i++)
        result[i] = a[i] ^ b[i];
}

void gf128_double(uint8_t *result, const uint8_t *input)
{
    uint8_t carry = 0;
    uint8_t temp[16];
    for (int i = 15; i >= 0; i--)
    {
        uint8_t b = input[i];
        uint8_t msb = b >> 7;
        temp[i] = (b << 1) | carry;
        carry = msb;
    }
    temp[15] ^= 0x87 * carry;
    memcpy(result, temp, 16);
}

bool tag_compare(const uint8_t *tag1, const uint8_t *tag2)
{
    uint8_t result = 0;
    for (int i = 0; i < 16; i++)
        result |= tag1[i] ^ tag2[i];
    return result == 0;
}

void aes_ctr_dec(uint8_t *output, const uint8_t *counter, const uint8_t *ciphertext, size_t ciphertext_len, const rkey_t *rkeys)
{
    uint8_t counter_block[16];
    uint8_t mask[16];
    uint32_t ctr;
    memcpy(counter_block, counter, 16);
    ctr = (counter_block[12] << 24) | (counter_block[13] << 16) | (counter_block[14] << 8) | counter_block[15];
    size_t blocks = ciphertext_len / 16;
    if (ciphertext_len % 16 != 0)
        blocks++;
    for (size_t i = 0; i < blocks; i++)
    {
        uint32_t current_ctr = ctr + i;
        counter_block[12] = (current_ctr >> 24) & 0xFF;
        counter_block[13] = (current_ctr >> 16) & 0xFF;
        counter_block[14] = (current_ctr >> 8) & 0xFF;
        counter_block[15] = current_ctr & 0xFF;
        aes128_encrypt_ffs(mask, mask, counter_block, counter_block, rkeys);
        size_t block_size = (i == blocks - 1 && ciphertext_len % 16 != 0) ? ciphertext_len % 16 : 16;
        for (size_t j = 0; j < block_size; j++)
            output[i * 16 + j] = ciphertext[i * 16 + j] ^ mask[j];
    }
}

void pmac(uint8_t *tag, const uint8_t *message_blocks, size_t num_blocks, const rkey_t *rkeys)
{
    uint8_t L[16];
    uint8_t zero_block[16] = {0};
    uint8_t masks[16];
    uint8_t acc[16] = {0};
    aes128_encrypt_ffs(L, L, zero_block, zero_block, rkeys);
    memcpy(masks, L, 16);
    for (size_t i = 0; i < num_blocks; i++)
    {
        uint8_t masked[16];
        const uint8_t *current_block = &message_blocks[i * 16];
        if (i == num_blocks - 1)
        {
            uint8_t final_block[16];
            int is_full_block = 1;
            if (is_full_block)
            {
                uint8_t last_mask[16];
                gf128_double(last_mask, masks);
                xor_blocks(final_block, current_block, last_mask);
            }
            else
            {
                memcpy(final_block, current_block, 16);
                final_block[16 - 1] ^= 0x80;
                xor_blocks(final_block, final_block, masks);
            }
            uint8_t cipher_out[16];
            aes128_encrypt_ffs(cipher_out, cipher_out, final_block, final_block, rkeys);
            xor_blocks(acc, acc, cipher_out);
        } 
        else
        {
            xor_blocks(masked, current_block, masks);
            uint8_t cipher_out[16];
            aes128_encrypt_ffs(cipher_out, cipher_out, masked, masked, rkeys);
            xor_blocks(acc, acc, cipher_out);
            gf128_double(masks, masks);
        }
    }
    aes128_encrypt_ffs(tag, tag, acc, acc, rkeys);
}

void digest(uint8_t *hash, const uint8_t *blocks, size_t num_blocks, const uint8_t *nonce)
{
    uint64_t sigma[2] = {0, 0};
    for (int i = 0; i < 12; i++)
        sigma[i / 8] += ((uint64_t)nonce[i]) << (8 * (i % 8));
    for (size_t i = 0; i < num_blocks; i++)
        for (int j = 0; j < 16; j++)
            sigma[j / 8] += ((uint64_t)blocks[i * 16 + j]) << (8 * (j % 8));
    memcpy(hash, sigma, 16);
}

// void digest(uint8_t *hash, const uint8_t *blocks, size_t num_blocks, const uint8_t *nonce)
// {
//     EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
//     const EVP_MD *md = EVP_sha256();
//     unsigned int md_len;
//     uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
//     EVP_DigestInit_ex(mdctx, md, NULL);
//     EVP_DigestUpdate(mdctx, nonce, 12);
//     EVP_DigestUpdate(mdctx, blocks, num_blocks * 16);
//     EVP_DigestFinal_ex(mdctx, sha256_hash, &md_len);
//     EVP_MD_CTX_free(mdctx);
//     // Truncate to 16 bytes to match the original function's output size
//     memcpy(hash, sha256_hash, 16);
// }

// void digest(uint8_t *hash, const uint8_t *blocks, size_t num_blocks, const uint8_t *nonce)
// {
//     mbedtls_md_context_t ctx;
//     const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
//     uint8_t sha256_hash[32];
//     mbedtls_md_init(&ctx);
//     mbedtls_md_setup(&ctx, md_info, 0);
//     mbedtls_md_starts(&ctx);
//     mbedtls_md_update(&ctx, nonce, 12);
//     mbedtls_md_update(&ctx, blocks, num_blocks * 16);
//     mbedtls_md_finish(&ctx, sha256_hash);
//     mbedtls_md_free(&ctx);
//     memcpy(hash, sha256_hash, 16);
// }

void enc_pmac_aes128(uint8_t *ciphertext, uint8_t *tag, const uint8_t *message, size_t message_len, const uint8_t *key, const uint8_t *nonce)
{
    rkey_t rkeys;
    aes128_keyschedule_ffs(&rkeys, key);
    uint8_t counter[16];
    memcpy(counter, nonce, 12);
    memset(counter + 12, 0, 3);
    counter[15] = 1;
    aes_ctr_dec(ciphertext, counter, message, message_len, &rkeys);
    size_t num_blocks = (message_len + 15) / 16;
    pmac(tag, ciphertext, num_blocks, &rkeys);
}

bool dec_pmac_aes128(uint8_t *message, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag, const uint8_t *key, const uint8_t *nonce)
{
    rkey_t rkeys;
    aes128_keyschedule_ffs(&rkeys, key);
    uint8_t counter[16];
    memcpy(counter, nonce, 12);
    memset(counter + 12, 0, 3);
    counter[15] = 1;
    aes_ctr_dec(message, counter, ciphertext, ciphertext_len, &rkeys);
    size_t num_blocks = ciphertext_len / 16;
    uint8_t computed_tag[16];
    pmac(computed_tag, ciphertext, num_blocks, &rkeys);
    return tag_compare(tag, computed_tag);
}

void enc_htmac_aes128(uint8_t *ciphertext, uint8_t *tag, const uint8_t *message, size_t message_len, const uint8_t *key, const uint8_t *nonce)
{
    rkey_t rkeys;
    aes128_keyschedule_ffs(&rkeys, key);
    uint8_t counter[16];
    memcpy(counter, nonce, 12);
    memset(counter + 12, 0, 3);
    counter[15] = 1;
    aes_ctr_dec(ciphertext, counter, message, message_len, &rkeys);
    size_t num_blocks = message_len / 16;
    uint8_t h[16];
    digest(h, ciphertext, num_blocks, nonce);
    aes128_encrypt_ffs(tag, tag, h, h, &rkeys);
}

bool dec_htmac_aes128(uint8_t *message, const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *tag, const uint8_t *key, const uint8_t *nonce) {
    rkey_t rkeys;
    aes128_keyschedule_ffs(&rkeys, key);
    uint8_t counter[16];
    memcpy(counter, nonce, 12);
    memset(counter + 12, 0, 3);
    counter[15] = 1;
    aes_ctr_dec(message, counter, ciphertext, ciphertext_len, &rkeys);
    size_t num_blocks = ciphertext_len / 16;
    uint8_t h[16];
    digest(h, ciphertext, num_blocks, nonce);
    uint8_t computed_tag[16];
    aes128_encrypt_ffs(computed_tag, computed_tag, h, h, &rkeys);
    return tag_compare(tag, computed_tag);
}