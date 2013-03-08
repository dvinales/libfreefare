#ifndef LIBFREEFARE_CRYPTO_AES_DES_H
#define LIBFREEFARE_CRYPTO_AES_DES_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#include <stdint.h>

#if defined(LIBFREEFARE_USE_OPENSSL)
  #include <openssl/aes.h>
  #include <openssl/des.h>

  typedef struct crypto_key_schedule {
    union {
      struct {
        DES_key_schedule ks1;
        DES_key_schedule ks2;
        DES_key_schedule ks3;
      };
      AES_KEY aes;
    };
  } crypto_key_schedule;

#elif defined(LIBFREEFARE_USE_POLARSSL)
  #include <polarssl/aes.h>
  #include <polarssl/des.h>

  typedef union crypto_key_schedule {
    des_context  des;
    des3_context des3;
    des3_context des3k3;
    aes_context  aes;
  } crypto_key_schedule;

#endif

void crypto_aes_set_encrypt_key(uint8_t*, size_t size, crypto_key_schedule* ks);
void crypto_aes_set_decrypt_key(uint8_t*, size_t size, crypto_key_schedule* ks);

void crypto_des_set_encrypt_key(uint8_t*, crypto_key_schedule* ks);
void crypto_des_set_decrypt_key(uint8_t*, crypto_key_schedule* ks);

void crypto_des3_set_encrypt_key(uint8_t*, crypto_key_schedule* ks);
void crypto_des3_set_decrypt_key(uint8_t*, crypto_key_schedule* ks);

void crypto_des3k3_set_encrypt_key(uint8_t*, crypto_key_schedule* ks);
void crypto_des3k3_set_decrypt_key(uint8_t*, crypto_key_schedule* ks);

void crypto_des_random_key(uint8_t* out);

void crypto_aes_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);
void crypto_aes_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);

void crypto_des_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);
void crypto_des_ecb_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);

void crypto_des3_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);
void crypto_des3_ecb_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);

void crypto_des3k3_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);
void crypto_des3k3_ecb_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks);

#endif // LIBFREEFARE_CRYPTO_AES_DES_H

