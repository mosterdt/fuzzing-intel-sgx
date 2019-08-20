#include <stdio.h>
#include <stdlib.h>
#include "../../common/debug.h"
#include "Enclave/encl_u.h"


void call_encl_f(int eid) {
    int rv = 0;
    char buf[0x5000];
    memset(buf, 'A', 0x5000);
    SGX_ASSERT_E( ecall_secret_lookup(eid, buf, strlen(buf)) );
}

