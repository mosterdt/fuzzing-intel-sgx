#include <stdio.h>
#include <stdlib.h>
#include "../../common/debug.h"
#include "Enclave/encl_u.h"


int enclave_size;
void *enclave_start;


void *get_random_pointer(void *e_start, int e_size){
    return ((rand() % (e_size>>4))<<4) + e_start;
}


void call_encl_f(int eid) {

    int rv = 1;
    char *buffer = (char *) malloc(0x1000);

    /*
    memset(buffer, 'A', 99);
    buffer[99] = 0x00;
    //ASSERT( !mprotect(GET_PFN(buffer), 0x4000, PROT_NONE) );
    // ocall on same page as segfault handler?
    //ASSERT( !mprotect(GET_PFN(ocall_print), 4096, PROT_NONE) );
    SGX_ASSERT_E( ecall_write_to_buffer(eid, buffer, 0x2001) );
    */

    //memset(buffer, 'A', 99);
    buffer[0] = 20
    for (int i=1; i < 100; i++) {
        void *p = get_random_pointer(enclave_start, enclave_size);
        memcopy(buffer, p, sizeof(p);
    }
    ASSERT( !mprotect(GET_PFN(buffer), 0x4000, PROT_NONE) );
    SGX_ASSERT_E( ecall_do_unsafe_bufcopy(eid, &rv, buffer) );


}

void setup_plug(int eid, int e_size, void *e_start) {
    enclave_size = e_size;
    enclave_start = e_start;
}


void ocall_print(char *p) {
	printf("%s\n", p);
}

