#include "crypto_random.h"

void crypto_random(uint8_t* out, size_t count)
{
    RAND_bytes(out, count);
}

