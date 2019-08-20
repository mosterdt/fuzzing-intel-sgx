#include <stdio.h>
#include <stdlib.h>
#include "../../common/debug.h"
#include "Enclave/encl_u.h"


void call_encl_f(int eid) {
    int rv = 0;
    SGX_ASSERT_E( ecall_dummy(eid, &rv, 1) );
    printf("what\n");
}


void ocall_print(const char *p) {
	printf("%s\n", p);
}

