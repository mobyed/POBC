#ifndef AES_OBC_H
#define AES_OBC_H

int aes_obc_encrypt(
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

#endif
