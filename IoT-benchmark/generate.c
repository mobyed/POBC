#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "aes/aes_gcm_siv.h"
#include "aes/aes_gcm.h"
#include "aes-pobc/aes_pobc.h"
#include "aes-pobc/aes_pobc_siv.h"
#include "aes-modes/aes_modes.h"
#include "eevee-forkskinny/jolteon.h"
#include "eevee-forkskinny/espeon.h"

static const char *HTMAC_AES = "htmac_aes";
static const char *PMAC_AES = "pmac_aes";
static const char *GCM_SIV_AES_128 = "aes_gcm_siv_128";
static const char *GCM_AES_128 = "aes_gcm_128";
static const char *POBC_AES = "aes_pobc";
static const char *POBC_SIV_AES = "aes_pobc_siv";
static const char *JOLTEON_AES_128 = "jolteon_aes_128";
static const char *ESPEON_AES_128 = "espeon_aes_128";

typedef int (*aead_enc_f)(
  /** ciphertext destination buffer */
  unsigned char *c,
  /** tag destination buffer */
  unsigned char *tag,
  /** message and message length */
  const unsigned char *m,unsigned long long mlen,
  /** associated data and AD length */
  const unsigned char *ad,unsigned long long adlen,
  /** nonce **/
  const unsigned char *npub,
  /** key **/
  const unsigned char *k
);

typedef int (*aead_dec_f)(
  /** message destination buffer */
  unsigned char *m,
  /** ciphertext and length */
  const unsigned char *c,unsigned long long clen,
  /** tag **/
  const unsigned char *tag,
  /** associated data and AD length */
  const unsigned char *ad,unsigned long long adlen,
  /** nonce **/
  const unsigned char *npub,
  /** key **/
  const unsigned char *k
);


void fill_rand(unsigned char *buf, unsigned int n)
{
    for(unsigned int i=0; i<n; i++)
        buf[i] = (unsigned char)rand();
}

void print_buf_hex(unsigned char *buf, unsigned int len)
{
  for(unsigned int i=0; i<len; i++)
    printf("%02x", buf[i]);
}

/* Adapter functions for POBC-SIV to match standard AEAD interface */
static int aead_pobc_siv_encrypt_wrapper(
    unsigned char *c,
    unsigned char *tag,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
)
{
    (void)npub;
    return aes_pobc_siv_encrypt(c, tag, m, mlen, ad, adlen, k);
}

static int aead_pobc_siv_decrypt_wrapper(
    unsigned char *m,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *tag,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
)
{
    (void)npub;
    return aes_pobc_siv_decrypt(m, c, clen, ad, adlen, tag, k);
}

/* Adapter functions for AES modes to match standard AEAD interface */
static int aead_htmac_aes_wrapper(
    unsigned char *c,
    unsigned char *tag,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
)
{
    (void)ad;
    (void)adlen;
    uint8_t *ciphertext = c;
    const uint8_t *message = m;
    const uint8_t *nonce = npub;
    const uint8_t *key = k;
    enc_htmac_aes128(ciphertext, tag, message, mlen, key, nonce);
    return 0;
}

static int aead_pmac_aes_wrapper(
    unsigned char *c,
    unsigned char *tag,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
)
{
    (void)ad;
    (void)adlen;
    uint8_t *ciphertext = c;
    const uint8_t *message = m;
    const uint8_t *nonce = npub;
    const uint8_t *key = k;
    enc_pmac_aes128(ciphertext, tag, message, mlen, key, nonce);
    return 0;
}

static int aead_htmac_aes_dec_wrapper(
    unsigned char *m,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *tag,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
)
{
    (void)ad;
    (void)adlen;
    
    uint8_t *message = m;
    const uint8_t *ciphertext = c;
    const uint8_t *nonce = npub;
    const uint8_t *key = k;
    
    int valid;
    valid = dec_htmac_aes128(message, ciphertext, clen, tag, key, nonce);
    return valid ? 0 : -1;
}

static int aead_pmac_aes_dec_wrapper(
    unsigned char *m,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *tag,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
)
{
    (void)ad;
    (void)adlen;
    
    uint8_t *message = m;
    const uint8_t *ciphertext = c;
    const uint8_t *nonce = npub;
    const uint8_t *key = k;
    
    int valid;
    valid = dec_pmac_aes128(message, ciphertext, clen, tag, key, nonce);
    return valid ? 0 : -1;
}

int generate_f(int mlen, int samples, int keylen, int noncelen, int taglen, aead_enc_f aead_enc, aead_dec_f aead_dec, int check) {
  unsigned char message[mlen];
  unsigned char key[keylen];
  unsigned char nonce[noncelen];
  unsigned char ciphertext[mlen];
  unsigned char tag[taglen];
  memset(ciphertext, 0, mlen);
  memset(tag, 0, taglen);
  unsigned char dec_message[mlen];
  srand(1);
  for(int i=0; i<samples; i++)
  {
    fill_rand(message, mlen);
    fill_rand(key, keylen);
    fill_rand(nonce, noncelen);
    int ret = aead_enc(ciphertext, tag, message, mlen, NULL, 0, nonce, key);
    assert(ret == 0);
    print_buf_hex(key, keylen);
    printf(" ");
    print_buf_hex(nonce, noncelen);
    printf(" ");
    print_buf_hex(message, mlen);
    printf(" ");
    if(check)
    {
      int tagcheck = aead_dec(dec_message, ciphertext, mlen, tag, NULL, 0, nonce, key);
      if(tagcheck != 0)
      {
        printf("Decryption failed!\n");
        return -1;
      }
      for(int i=0; i<mlen; i++)
      {
        if(message[i] != dec_message[i])
        {
          printf("Decrypted message mismatch\n");
          return -1;
        }
      }
    }
    print_buf_hex(ciphertext, mlen);
    printf(" ");
    print_buf_hex(tag, taglen);
    printf("\n");
  }
  return 0;
}

int generate(const char *primitive, int mlen, int samples, int check)
{
  int keylen;
  int noncelen;
  int taglen;
  aead_enc_f aead_enc = NULL;
  aead_dec_f aead_dec = NULL;
  if(strncmp(GCM_SIV_AES_128, primitive, strlen(GCM_SIV_AES_128)) == 0)
  {
    keylen = 128/8;
    noncelen = 96/8;
    taglen = 128/8;
    aead_enc = aes_gcm_siv_128_encrypt;
    if(check)
    {
      printf("--check not supported for primitive %s\n", GCM_SIV_AES_128);
      return -2;
    }
  }
  else if(strncmp(GCM_AES_128, primitive, strlen(GCM_AES_128)) == 0)
  {
    keylen = 128/8;
    noncelen = 96/8;
    taglen = 128/8;
    aead_enc = aes_gcm_128_encrypt;
    if(check)
    {
      printf("--check not supported for primitive %s\n", GCM_AES_128);
      return -2;
    }
  }
  else if(strncmp(POBC_AES, primitive, strlen(POBC_AES)) == 0)
  {
    keylen = 16;
    noncelen = 12;
    taglen = 16;
    aead_enc = aes_pobc_encrypt;
    aead_dec = NULL;
    if(check)
    {
        printf("--check not supported for primitive %s\n", POBC_AES);
        return -2;
    }
  }
  else if(strncmp(POBC_SIV_AES, primitive, strlen(POBC_SIV_AES)) == 0)
  {
    keylen = 16;
    noncelen = 16;
    taglen = 16;
    aead_enc = aead_pobc_siv_encrypt_wrapper;
    aead_dec = aead_pobc_siv_decrypt_wrapper;
  }
  else if(strncmp(HTMAC_AES, primitive, strlen(HTMAC_AES)) == 0)
  {
    keylen = 16; // 128 bits
    noncelen = 12; // 96 bits
    taglen = 16; // 128 bits
    aead_enc = aead_htmac_aes_wrapper;
    aead_dec = aead_htmac_aes_dec_wrapper;
  }
  else if(strncmp(PMAC_AES, primitive, strlen(PMAC_AES)) == 0)
  {
    keylen = 16; // 128 bits
    noncelen = 12; // 96 bits
    taglen = 16; // 128 bits
    aead_enc = aead_pmac_aes_wrapper;
    aead_dec = aead_pmac_aes_dec_wrapper;
  }
  else if(strncmp(JOLTEON_AES_128, primitive, strlen(JOLTEON_AES_128)) == 0)
  {
    keylen = 2*(128/8);
    noncelen = 112/8;
    taglen = 128/8;
    aead_enc = jolteon_aes_128_encrypt;
    if(check)
    {
      printf("--check not supported for primitive %s\n", JOLTEON_AES_128);
      return -2;
    }
  }
  else if(strncmp(ESPEON_AES_128, primitive, strlen(ESPEON_AES_128)) == 0)
  {
    keylen = 2*(128/8);
    noncelen = 128/8;
    taglen = 128/8;
    aead_enc = espeon_aes_128_encrypt;
    if(check)
    {
      printf("--check not supported for primitive %s\n", ESPEON_AES_128);
      return -2;
    }
  }
  else
  {
    assert(0);
  }
  return generate_f(mlen, samples, keylen, noncelen, taglen, aead_enc, aead_dec, check);
}

int check_supported_primitive(const char *input)
{
  if (strncmp(GCM_SIV_AES_128, input, strlen(GCM_SIV_AES_128)) == 0)
    return 0;
  if (strncmp(GCM_AES_128, input, strlen(GCM_AES_128)) == 0)
    return 0;
  if (strncmp(POBC_AES, input, strlen(POBC_AES)) == 0)
    return 0;
  if (strncmp(POBC_SIV_AES, input, strlen(POBC_SIV_AES)) == 0)
    return 0;
  if (strncmp(HTMAC_AES, input, strlen(HTMAC_AES)) == 0)
    return 0;
  if (strncmp(PMAC_AES, input, strlen(PMAC_AES)) == 0)
    return 0;
  if (strncmp(JOLTEON_AES_128, input, strlen(JOLTEON_AES_128)) == 0)
    return 0;
  if (strncmp(ESPEON_AES_128, input, strlen(ESPEON_AES_128)) == 0)
    return 0;
  return 1;
}

int main(int argc, char* argv[])
{
  if(argc <= 2)
  {
    printf("%s [--check] primitive (mlen samples)+\n", argv[0]);
    printf("\t--check:\t check if encryption produces a valid ciphertext\n");
    printf("\tsupported primitives:\n");
    printf("\t\t%s\n", GCM_SIV_AES_128);
    printf("\t\t%s\n", GCM_AES_128);
    printf("\t\t%s\n", POBC_AES);
    printf("\t\t%s\n", POBC_SIV_AES);
    printf("\t\t%s\n", HTMAC_AES);
    printf("\t\t%s\n", PMAC_AES);
    printf("\t\t%s\n", JOLTEON_AES_128);
    printf("\t\t%s\n", ESPEON_AES_128);
    printf("\n\tmlen samples: the number of testvectors to generate for each message length mlen\n");
    return 1;
  }
  unsigned offset = 0;
  int check = 0;
  if(strcmp("--check", argv[1]) == 0)
  {
    offset += 1;
    check = 1;
  }
  char *primitive = argv[offset+1];
  if(check_supported_primitive(primitive))
  {
    printf("Unsupported primitive %s\n", primitive);
    return 2;
  }
  int pairs= (argc-2-offset)/2;
  int mlen[pairs];
  int samples[pairs];
  for(int i=0; i<pairs; i++)
  {
    mlen[i] = strtol(argv[offset + 2 + 2*i], NULL, 10);
    if(mlen[i] == 0)
    {
      printf("Cannot parse %s as decimal number\n", argv[offset + 2 + 2*i]);
      return 3;
    }
    samples[i] = strtol(argv[offset + 2 + 2*i+1], NULL, 10);
    if(samples[i] == 0)
    {
      printf("Cannot parse %s as decimal number\n", argv[offset + 2 + 2*i + 1]);
      return 3;
    }
  }
  for(int i=0; i<pairs; i++)
  {
    // printf("Generate %d %d (%d)", mlen[i], samples[i], pairs);
    int success = generate(primitive, mlen[i], samples[i], check);
    if(success != 0)
      return success;
  }
  return 0;
}