#include "encl_t.h"
#include <string.h>

int super_secret_constant   = 0xdeadbeef;

int ecall_dummy(int j)
{
    for (int i=0; i < 5; i++) {
        if (i == 2)
            j++;
    }
    return super_secret_constant + j;
}

