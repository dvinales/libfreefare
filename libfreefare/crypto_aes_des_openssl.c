#include "crypto_aes_des.h"

void crypto_aes_set_encrypt_key(uint8_t* key, size_t size, crypto_key_schedule* ks)
{
  AES_set_encrypt_key(key, size, &ks->aes);
}

void crypto_aes_set_decrypt_key(uint8_t* key, size_t size, crypto_key_schedule* ks)
{
  AES_set_decrypt_key(key, size, &ks->aes);
}

void crypto_des_set_encrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  DES_set_key(key, &ks->ks1);
}

void crypto_des3_set_encrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  DES_set_key(key + 0, &ks->ks1);
  DES_set_key(key + 8, &ks->ks2);
}

void crypto_des3k3_set_encrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  DES_set_key(key +  0, &ks->ks1);
  DES_set_key(key +  8, &ks->ks2);
  DES_set_key(key + 16, &ks->ks3);
}

void crypto_des_set_decrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  // In OpenSSL it's the same thing for encrypt and decrypt.
  crypto_des_set_encrypt_key(key, ks);
}

void crypto_des3_set_decrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  // In OpenSSL it's the same thing for encrypt and decrypt.
  crypto_des3_set_encrypt_key(key, ks);
}

void crypto_des3k3_set_decrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  // In OpenSSL it's the same thing for encrypt and decrypt.
  crypto_des3k3_set_encrypt_key(key, ks);
}

void crypto_des_random_key(uint8_t* out)
{
  DES_random_key(out);
}

void crypto_aes_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  AES_encrypt(in, out, &ks->aes);
}

void crypto_aes_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  AES_decrypt(in, out, &ks->aes);
}

void crypto_des_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out, &ks->ks1, DES_ENCRYPT);
}

void crypto_des_ecb_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out, &ks->ks1, DES_DECRYPT);
}

void crypto_des3_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks1, DES_ENCRYPT);
  DES_ecb_encrypt((DES_cblock *)out, (DES_cblock *)in,  &ks->ks2, DES_DECRYPT);
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks1, DES_ENCRYPT);
}

void crypto_des3_ecb_decrypt(uint8_t const* in, uint8_t* out, crypto_key_schedule* ks)
{
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks1, DES_DECRYPT);
  DES_ecb_encrypt((DES_cblock *)out, (DES_cblock *)in,  &ks->ks2, DES_ENCRYPT);
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks1, DES_DECRYPT);
}

void crypto_des3k3_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks1, DES_ENCRYPT);
  DES_ecb_encrypt((DES_cblock *)out, (DES_cblock *)in,  &ks->ks2, DES_DECRYPT);
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks3, DES_ENCRYPT);
}

void crypto_des3k3_ecb_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks3, DES_DECRYPT);
  DES_ecb_encrypt((DES_cblock *)out, (DES_cblock *)in,  &ks->ks2, DES_ENCRYPT);
  DES_ecb_encrypt((DES_cblock *)in,  (DES_cblock *)out, &ks->ks1, DES_DECRYPT);
}

