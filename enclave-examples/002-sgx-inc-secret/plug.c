#include <stdio.h>
#include <stdlib.h>
#include "../../common/debug.h"
#include "Enclave/encl_u.h"

//int i = 0;

void call_encl_f(int eid) {
    int rv = 0;
    SGX_ASSERT_E( ecall_inc_secret_maccess(eid, 0) );
    //SGX_ASSERT_E( ecall_check_a(eid, &rv) );
    printf("%d\n", rv);
}

void setup_plug(int eid, int e_size, void *e_start) {

}



