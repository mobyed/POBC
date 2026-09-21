#include "aes_pobc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <mbedtls/aes.h>

#define AES_BLOCK_LEN 16
#define AES_LLAMA_NONCE_LEN 12

static inline void nonce_incr(unsigned char y[16])
{
    uint32_t *counter = (uint32_t*)(y + 12);
    (*counter)++;
    if (*counter == 0)
        for (int i = 11; i >= 0; i--)
            if (++y[i] != 0) break;
}

static inline void aes_ecb_encrypt_safe(mbedtls_aes_context *ctx, const unsigned char in[AES_BLOCK_LEN], unsigned char out[AES_BLOCK_LEN])
{
    unsigned char tmp_in[AES_BLOCK_LEN];
    memcpy(tmp_in, in, AES_BLOCK_LEN);
    mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, tmp_in, out);
}

static inline void process_blocks(mbedtls_aes_context *ctx, const unsigned char *data,  unsigned long long datalen, unsigned char *tag, unsigned char nonce_prefix)
{
    unsigned char nonce_tmp[AES_BLOCK_LEN] = {0};
    unsigned char tag_block[AES_BLOCK_LEN];
    unsigned long long blocks = (datalen + AES_BLOCK_LEN - 1) / AES_BLOCK_LEN;
    nonce_tmp[12] = nonce_prefix;
    nonce_tmp[15] = 1;
    for (unsigned long long b = 0; b < blocks; b++)
    {
        aes_ecb_encrypt_safe(ctx, nonce_tmp, tag_block);
        size_t offset = b * AES_BLOCK_LEN;
        size_t limit = (datalen - offset) < AES_BLOCK_LEN ? (datalen - offset) : AES_BLOCK_LEN;
        for (size_t j = 0; j < limit; j++)
            tag[j] ^= tag_block[j] ^ data[offset + j];
        nonce_incr(nonce_tmp);
    }
}

int aes_pobc_encrypt(unsigned char *restrict c, unsigned char *restrict tag, const unsigned char *restrict m, unsigned long long mlen, const unsigned char *restrict ad, unsigned long long adlen, const unsigned char *restrict npub, const unsigned char *restrict k)
{
    mbedtls_aes_context ctx;
    unsigned char nonce_counter[AES_BLOCK_LEN] = {0};
    unsigned char stream_block[AES_BLOCK_LEN];
    unsigned long long i = 0;
    int ret = mbedtls_aes_setkey_enc(&ctx, k, 128);
    if (ret != 0)
        return ret;
    memcpy(nonce_counter, npub, AES_LLAMA_NONCE_LEN);
    aes_ecb_encrypt_safe(&ctx, nonce_counter, tag);
    nonce_counter[15] = 0x01;
    while (i + AES_BLOCK_LEN <= mlen)
    {
        aes_ecb_encrypt_safe(&ctx, nonce_counter, stream_block);
        for (size_t j = 0; j < AES_BLOCK_LEN; j++)
            c[i + j] = m[i + j] ^ stream_block[j];
        nonce_incr(nonce_counter);
        i += AES_BLOCK_LEN;
    }
    if (i < mlen)
    {
        aes_ecb_encrypt_safe(&ctx, nonce_counter, stream_block);
        for (; i < mlen; i++)
            c[i] = m[i] ^ stream_block[i % AES_BLOCK_LEN];
    }
    process_blocks(&ctx, ad, adlen, tag, 0x60);
    process_blocks(&ctx, c, mlen, tag, 0x40);
    mbedtls_aes_free(&ctx);
    return 0;
}