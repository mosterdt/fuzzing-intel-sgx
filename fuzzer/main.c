/* utility headers */
#include "debug.h"
#include "pf.h"
#include <sys/mman.h>

/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "Enclave/encl_u.h"


#include "libsgxstep/apic.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/config.h"
#include "libsgxstep/idt.h"
#include "libsgxstep/config.h"


sgx_enclave_id_t create_enclave(void)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_enclave_id_t eid = -1;

    info_event("Creating enclave...");
    SGX_ASSERT_E( sgx_create_enclave( "./Enclave/encl.so", /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );

    return eid;
}

int fault_fired = 0;
void *ebase_address = NULL;
int enc_size = 0;
int working_window = 1;

#define SEQ_LEN 10
void *seq[SEQ_LEN];


void handle_in_enclave(void *base_adrs) {
    int p_offset = (base_adrs - ebase_address) >> 12;

    // enclave page in lower range
    if (fault_fired > working_window && p_offset < 200)
        mprotect(GET_PFN(seq[(fault_fired-working_window)%SEQ_LEN]), 4096, PROT_NONE);
    if (p_offset < 200)
        seq[fault_fired++ %SEQ_LEN] = base_adrs;
    mprotect(GET_PFN(base_adrs), 4096, PROT_WRITE|PROT_READ|PROT_EXEC);
    printf("pfn=%p, ba=%p, offset: %d\n", GET_PFN(base_adrs), base_adrs, p_offset);

}

void handle_outside_enclave(void *base_adrs) {
    if (fault_fired > working_window)
        mprotect(GET_PFN(seq[(fault_fired-working_window)%SEQ_LEN]), 4096, PROT_NONE);
    seq[fault_fired++ %SEQ_LEN] = base_adrs;
    mprotect(GET_PFN(base_adrs), 4096, PROT_WRITE|PROT_READ|PROT_EXEC);
    printf("out enclave: pfn=%p, ba=%p, loc: %d\n",
            GET_PFN(base_adrs), base_adrs, base_adrs - GET_PFN(base_adrs));

}

void fault_handler(void *base_adrs)
{
    if (ebase_address <= base_adrs && base_adrs <= ebase_address + enc_size) {
        handle_in_enclave(base_adrs);
    } else if (base_adrs == NULL) {
        printf("null pointer\n");
        abort();
    } else {
        handle_outside_enclave(base_adrs);
    }

}

void protect_memory(void *base_adrs, int size) {
    for (int i=0; i <= size; i += 0x1000) {
        if ( mprotect(base_adrs+i, 4096, PROT_NONE) == 0 ) {
            //printf("protected address %p\n", base_adrs+i);
        } else {
            printf("failed to protect address %p\n", base_adrs+i);
        }
    }
    printf("protected %d addresses\n", size/0x1000);
}

void restore_memory(void *base_adrs, int size) {
    for (int i=0; i <= size; i += 0x1000) {
        //printf("protected address %p\n", base_adrs+i);
        mprotect(base_adrs+i, 4096, PROT_WRITE|PROT_READ|PROT_EXEC); 
    }
    printf("restored %d addresses\n", size/0x1000);
}

int main( int argc, char **argv )
{
    sgx_enclave_id_t eid = create_enclave();

    info("registering fault handler..");
    register_fault_handler(fault_handler);

    register_enclave_info();
    print_enclave_info();

    ebase_address = get_enclave_base();
    enc_size = get_enclave_size();

    // randomthings
    srand(1);


    /* ---------------------------------------------------------------------- */

    int rv = 1;
    int cipher, plain;
    char *buffer = (char *) malloc(0x4000);


    fault_fired = 0;
    getchar();
    protect_memory(get_enclave_base(), get_enclave_size());
    cipher = rand();
    SGX_ASSERT_E( ecall_rsa_decode(eid, &plain, cipher) );
    printf("pagefaults: %d\n", fault_fired);


    fault_fired = 0;
    getchar();
    protect_memory(get_enclave_base(), get_enclave_size());
    for (int i=0; i < 99; i++)
        buffer[i] = 'A';
    buffer[99] = 0x00;
    ASSERT( !mprotect(GET_PFN(buffer), 0x4000, PROT_NONE) );
    // ocall on same page as segfault handler?
    //ASSERT( !mprotect(GET_PFN(ocall_print), 4096, PROT_NONE) );
    SGX_ASSERT_E( ecall_write_to_buffer(eid, buffer, 0x2001) );
    printf("pagefaults: %d\n", fault_fired);

    fault_fired = 0;
    getchar();
    protect_memory(get_enclave_base(), get_enclave_size());
    buffer[0] = 10;
    for (int i=1; i < 99; i++)
        buffer[i] = 'A';
    buffer[99] = 0x00;
    ASSERT( !mprotect(GET_PFN(buffer), 0x4000, PROT_NONE) );
    SGX_ASSERT_E( ecall_do_unsafe_bufcopy(eid, &rv, buffer) );
    printf("pagefaults: %d\n", fault_fired);

    /* ---------------------------------------------------------------------- */


    restore_memory(get_enclave_base(), get_enclave_size());
    info_event("destroying SGX enclave");
    SGX_ASSERT_E( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}


void ocall_print(char *p) {
	printf("%s\n", p);
}

