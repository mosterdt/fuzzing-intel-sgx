#include "encl_t.h"
#include <string.h>

int super_secret_constant   = 0xdeadbeef;

void ecall_pointer_string(char *str) {
    volatile int b = 0;
}

