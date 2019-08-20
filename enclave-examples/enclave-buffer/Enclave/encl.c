#include "encl_t.h"
#include <sgx_trts.h>


int ecall_do_unsafe_bufcopy(char *buf) {
    
    ocall_print("abc");

    volatile char tooshort[10];
    char length = buf[0];


    for (nint i=1; i < length; i++){
        tooshort[i] = buf[i];
    }
    
    ocall_print("done");
    return 0;
}

void ecall_write_to_buffer(char *buf, int length) {
    for (int i = 0; i < length; i++)
        buf[i] = 'B';
}
