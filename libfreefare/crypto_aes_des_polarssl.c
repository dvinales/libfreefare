#include "crypto_aes_des.h"
#include "crypto_random.h"
#include "freefare_internal.h"

void crypto_aes_set_encrypt_key(uint8_t* key, size_t size, crypto_key_schedule* ks)
{
  aes_setkey_enc(&ks->enc.aes, key, size);
}

void crypto_aes_set_decrypt_key(uint8_t* key, size_t size, crypto_key_schedule* ks)
{
  aes_setkey_dec(&ks->dec.aes, key, size);
}

void crypto_des_set_encrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  des_setkey_enc(&ks->enc.des, key);
}

void crypto_des3_set_encrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  des3_set2key_enc(&ks->enc.des3, key);
}

void crypto_des3k3_set_encrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  des3_set3key_enc(&ks->enc.des3k3, key);
}

void crypto_des_set_decrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  des_setkey_dec(&ks->dec.des, key);
}

void crypto_des3_set_decrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  des3_set2key_dec(&ks->dec.des3, key);
}

void crypto_des3k3_set_decrypt_key(uint8_t* key, crypto_key_schedule* ks)
{
  des3_set3key_dec(&ks->dec.des3k3, key);
}

void crypto_des_random_key(uint8_t* key)
{
  do
  {
    crypto_random(key, DES_KEY_SIZE);
  } while (des_key_check_weak(key));

  des_key_set_parity(key);
}

void crypto_aes_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  aes_crypt_ecb(&ks->enc.aes, AES_ENCRYPT, in, out);
}

void crypto_aes_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  aes_crypt_ecb(&ks->dec.aes, AES_DECRYPT, in, out);
}

void crypto_des_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  des_crypt_ecb(&ks->enc.des, in, out);
}

void crypto_des_ecb_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  des_crypt_ecb(&ks->dec.des, in, out);
}

void crypto_des3_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  des3_crypt_ecb(&ks->enc.des3, in, out);    //  Key schedules must be up to date
}

void crypto_des3_ecb_decrypt(uint8_t const* in, uint8_t* out, crypto_key_schedule* ks)
{
  des3_crypt_ecb(&ks->dec.des3, in, out);    //  Key schedules must be up to date
}

void crypto_des3k3_ecb_encrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  des3_crypt_ecb(&ks->enc.des3k3, in, out);    //  Key schedules must be up to date
}

void crypto_des3k3_ecb_decrypt(const uint8_t* in, uint8_t* out, crypto_key_schedule* ks)
{
  des3_crypt_ecb(&ks->dec.des3k3, in, out);    //  Key schedules must be up to date
}
