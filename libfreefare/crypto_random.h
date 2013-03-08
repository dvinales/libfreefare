#ifndef LIBFREEFARE_CRYPTO_RANDOM_H
#define LIBFREEFARE_CRYPTO_RANDOM_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#if defined(LIBFREEFARE_USE_OPENSSL)
  #include <openssl/rand.h>
#elif defined(LIBFREEFARE_USE_POLARSSL)
  #include <polarssl/havege.h>
#endif

#include <stddef.h>
#include <stdint.h>

void crypto_random(uint8_t* out, size_t count);

#endif // LIBFREEFARE_CRYPTO_RANDOM_H
