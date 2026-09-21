#include "aes_pobc_siv.h"
#include <string.h>
#include <mbedtls/aes.h>

#define AES_BLOCK_LEN 16

static void gcm_incr(unsigned char y[16])
{
    size_t i;
    for (i = 16; i > 12; i--)
        if (++y[i - 1] != 0)
            break;
}

static inline void aes_ecb_encrypt_safe(mbedtls_aes_context *ctx, const unsigned char in[AES_BLOCK_LEN], unsigned char out[AES_BLOCK_LEN])
{
    unsigned char tmp_in[AES_BLOCK_LEN];
    memcpy(tmp_in, in, AES_BLOCK_LEN);
    mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, tmp_in, out);
}

static int pobc_mac(unsigned char *iv, const unsigned char *ad, unsigned long long adlen, const unsigned char *m, unsigned long long mlen, const unsigned char *k)
{
    mbedtls_aes_context ctx;
    unsigned char y[AES_BLOCK_LEN] = {0};
    unsigned char nonce[AES_BLOCK_LEN];
    unsigned char block[AES_BLOCK_LEN];
    mbedtls_aes_init(&ctx);
    int ret = mbedtls_aes_setkey_enc(&ctx, k, 128);
    if (ret != 0)
    {
        mbedtls_aes_free(&ctx);
        return ret;
    }
    memset(nonce, 0, AES_BLOCK_LEN);
    nonce[0] = 0x01;
    unsigned long long ad_blocks = adlen / AES_BLOCK_LEN + 1;
    for (unsigned long long i = 0; i < ad_blocks; i++)
    {
        memset(block, 0, AES_BLOCK_LEN);
        size_t copy_len = (adlen - i * AES_BLOCK_LEN) < AES_BLOCK_LEN ? (size_t)(adlen - i * AES_BLOCK_LEN) : (size_t)AES_BLOCK_LEN;
        if (copy_len > 0)
            memcpy(block, ad + i * AES_BLOCK_LEN, copy_len);
        if (copy_len < AES_BLOCK_LEN)
            block[copy_len] = 0x80;
        for (int j = 0; j < AES_BLOCK_LEN; j++)
            nonce[j] ^= block[j];
        aes_ecb_encrypt_safe(&ctx, nonce, block);
        for (int j = 0; j < AES_BLOCK_LEN; j++)
            y[j] ^= block[j];
        gcm_incr(nonce);
    }
    memset(nonce, 0, AES_BLOCK_LEN);
    nonce[0] = 0x01;
    unsigned long long m_blocks = mlen / AES_BLOCK_LEN + 1;
    for (unsigned long long i = 0; i < m_blocks; i++)
    {
        memset(block, 0, AES_BLOCK_LEN);
        size_t copy_len = (mlen - i * AES_BLOCK_LEN) < AES_BLOCK_LEN ? (size_t)(mlen - i * AES_BLOCK_LEN) : (size_t)AES_BLOCK_LEN;
        if (copy_len > 0)
            memcpy(block, m + i * AES_BLOCK_LEN, copy_len);
        if (copy_len < AES_BLOCK_LEN)
            block[copy_len] = 0x80;
        for (int j = 0; j < AES_BLOCK_LEN; j++)
            nonce[j] ^= block[j];
        aes_ecb_encrypt_safe(&ctx, nonce, block);
        for (int j = 0; j < AES_BLOCK_LEN; j++)
            y[j] ^= block[j];
        gcm_incr(nonce);
    }
    unsigned char final_nonce[AES_BLOCK_LEN] = {0};
    final_nonce[0] = 0x00;
    memcpy(final_nonce + 1, y + 1, AES_BLOCK_LEN - 1);
    aes_ecb_encrypt_safe(&ctx, final_nonce, iv);
    mbedtls_aes_free(&ctx);
    return 0;
}

int aes_pobc_siv_encrypt(unsigned char *c, unsigned char *iv, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *k)
{
    int ret = pobc_mac(iv, ad, adlen, m, mlen, k);
    if (ret != 0)
        return ret;
    mbedtls_aes_context ctx;
    unsigned char nonce_counter[AES_BLOCK_LEN];
    unsigned char stream_block[AES_BLOCK_LEN];
    unsigned long long i = 0;
    mbedtls_aes_init(&ctx);
    ret = mbedtls_aes_setkey_enc(&ctx, k, 128);
    if (ret != 0)
    {
        mbedtls_aes_free(&ctx);
        return ret;
    }
    memcpy(nonce_counter, iv, AES_BLOCK_LEN);
    while (i < mlen)
    {
        aes_ecb_encrypt_safe(&ctx, nonce_counter, stream_block);
        size_t chunk = (mlen - i) < AES_BLOCK_LEN ? (size_t)(mlen - i) : (size_t)AES_BLOCK_LEN;
        for (size_t j = 0; j < chunk; j++)
            c[i + j] = m[i + j] ^ stream_block[j];
        gcm_incr(nonce_counter);
        i += chunk;
    }
    mbedtls_aes_free(&ctx);
    return 0;
}

int aes_pobc_siv_decrypt(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *iv, const unsigned char *k)
{
    mbedtls_aes_context ctx;
    unsigned char nonce_counter[AES_BLOCK_LEN];
    unsigned char stream_block[AES_BLOCK_LEN];
    unsigned long long i = 0;
    mbedtls_aes_init(&ctx);
    int ret = mbedtls_aes_setkey_enc(&ctx, k, 128);
    if (ret != 0)
    {
        mbedtls_aes_free(&ctx);
        return ret;
    }
    memcpy(nonce_counter, iv, AES_BLOCK_LEN);
    while (i < clen)
    {
        aes_ecb_encrypt_safe(&ctx, nonce_counter, stream_block);
        size_t chunk = (clen - i) < AES_BLOCK_LEN ? (size_t)(clen - i) : (size_t)AES_BLOCK_LEN;
        for (size_t j = 0; j < chunk; j++)
            m[i + j] = c[i + j] ^ stream_block[j];
        gcm_incr(nonce_counter);
        i += chunk;
    }
    mbedtls_aes_free(&ctx);
    unsigned char iv_recomputed[AES_BLOCK_LEN];
    ret = pobc_mac(iv_recomputed, ad, adlen, m, clen, k);
    if (ret != 0)
        return ret;
    if (memcmp(iv, iv_recomputed, AES_BLOCK_LEN) != 0)
    {
        memset(m, 0, (size_t)clen);
        return -1;
    }
    return 0;
}