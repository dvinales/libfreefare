#include "crypto_random.h"
#include "assert.h"

static havege_state* havege()
{
    static havege_state hs;
    havege_init(&hs);
    return &hs;
}

void crypto_random(uint8_t* out, size_t count)
{
    static havege_state* hs = NULL;
    if (hs == NULL)
        hs = havege();
    assert(hs != NULL);
    havege_random(hs, out, count);
}

