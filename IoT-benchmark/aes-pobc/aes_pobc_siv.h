#ifndef AES_POBC_SIV_H
#define AES_POBC_SIV_H

int aes_pobc_siv_encrypt(
  /** ciphertext destination buffer */
  unsigned char *c,
  /** initialization vector (tag) destination buffer */
  unsigned char *iv,
  /** message and message length */
  const unsigned char *m, unsigned long long mlen,
  /** associated data and AD length */
  const unsigned char *ad, unsigned long long adlen,
  /** key **/
  const unsigned char *k
);

int aes_pobc_siv_decrypt(
  /** plaintext destination buffer */
  unsigned char *m,
  /** ciphertext and ciphertext length */
  const unsigned char *c, unsigned long long clen,
  /** associated data and AD length */
  const unsigned char *ad, unsigned long long adlen,
  /** initialization vector (tag) */
  const unsigned char *iv,
  /** key **/
  const unsigned char *k
);

#endif