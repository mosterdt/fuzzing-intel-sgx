#include <stdio.h>
#include <stdlib.h>
#include "../../common/debug.h"
#include "Enclave/encl_u.h"


int enclave_size;
void *enclave_start;
void *secret_pt;


void *get_random_pointer(void *e_start, int e_size){
    return ((rand() % (e_size>>4))<<4) + e_start;
}


void call_encl_f(int eid) {
    char *s = "bUHhhhhhDDDDDDDDDDDDddD";
    printf("%p\n", s);
    void *rand_pointer = get_random_pointer(enclave_start, enclave_size);
    printf("%#p, %#p\n", enclave_start, rand_pointer);
    getchar();
    SGX_ASSERT_E( ecall_to_lowercase(eid, rand_pointer) );
    printf("string: %s\n", s);
}


void setup_plug(int eid, int e_size, void *e_start) {
    enclave_size = e_size;
    enclave_start = e_start;
    SGX_ASSERT_E( ecall_set_secret(eid, 0) );
    SGX_ASSERT_E( ecall_get_secret_adrs(eid, &secret_pt) );
}


void ocall_print(const char *p) {
	printf("%s\n", p);
}

