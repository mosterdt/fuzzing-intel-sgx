#include <stdio.h>
#include <stdlib.h>
#include "../../common/debug.h"
#include "Enclave/encl_u.h"


void call_encl_f(int eid) {
    int rv = 1;
    SGX_ASSERT_E( ecall_reset_secret(eid, &rv) );
    SGX_ASSERT_E( ecall_rsa_decode(eid, &rv, 888) );
}

void setup_plug(int eid, int e_size, void *e_start) {

}
