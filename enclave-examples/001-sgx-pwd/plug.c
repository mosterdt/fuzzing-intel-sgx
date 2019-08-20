#include <stdio.h>
#include <stdlib.h>
#include "../../common/debug.h"
#include "Enclave/encl_u.h"


void call_encl_f(int eid) {
    int rv = 1;
    int secret = 0;
    char *pwd = "tehst";
    SGX_ASSERT_E( ecall_get_secret(eid, &rv, &secret, pwd) );
    //SGX_ASSERT_E( ecall_dummy(eid, &rv, 1) );
    printf("secret: %d\n", secret);
}


void ocall_print(const char *p) {
	printf("%s\n", p);
}

