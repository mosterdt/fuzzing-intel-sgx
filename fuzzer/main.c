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


#define RSA_TEST_VAL    1234

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
void *pv_pt = NULL, *ppv_pt = NULL, *ebase_address = NULL;
void *sq_pt = NULL, *mul_pt = NULL, *modpow_pt = NULL;

#define SEQ_LEN 100
void *seq[SEQ_LEN];
int seqp = 0;

void fault_handler(void *base_adrs)
{

    //seq[seqp++%SEQ_LEN] = base_adrs;
    if (fault_fired > 1) //ppv_pt - GET_PFN(ppv_pt) != 0xFFF && 
        mprotect(GET_PFN(ppv_pt), 4096, PROT_NONE);
    ppv_pt = pv_pt;
    pv_pt = base_adrs;
    mprotect(GET_PFN(base_adrs), 4096, PROT_WRITE|PROT_READ|PROT_EXEC);
    printf("offset: %d, pfn=%p, ba=%p\n", (base_adrs - ebase_address) >> 12, GET_PFN(base_adrs),base_adrs );

    fault_fired++;
}

void protect_memory(void *base_adrs, int size) {
    for (int i=0; i <= size; i += 0x1000) {
        printf("protected address %p\n", base_adrs+i);
        mprotect(base_adrs+i, 4096, PROT_NONE);
    }
}

int main( int argc, char **argv )
{
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 0;
    int cipher, plain;

    /* ---------------------------------------------------------------------- */
    info("registering fault handler..");
    register_fault_handler(fault_handler);

    /* ---------------------------------------------------------------------- */
    info_event("Calling enclave..");
    SGX_ASSERT_E( ecall_get_square_adrs(eid, &sq_pt) );
    SGX_ASSERT_E( ecall_get_multiply_adrs(eid, &mul_pt) );
    SGX_ASSERT_E( ecall_get_modpow_adrs(eid, &modpow_pt) );
    modpow_pt = (void*) (((uint64_t) modpow_pt) & ~0xfff);
    info("square at %p; muliply at %p; modpow at %p", sq_pt, mul_pt, modpow_pt);

    SGX_ASSERT_E( ecall_rsa_encode(eid, &cipher, RSA_TEST_VAL) );
    SGX_ASSERT_E( ecall_rsa_decode(eid, &plain, cipher) );
    info("secure enclave encrypted '%d' to '%d'; decrypted '%d'", RSA_TEST_VAL, cipher, plain);
    info("base address = %p", get_enclave_base());
    info("base size= %p", get_enclave_size());
    info("tcs %p\n", sgx_get_tcs());
    ebase_address = get_enclave_base();

    register_enclave_info();
    print_enclave_info();


    for (int i=0; i < SEQ_LEN; i++)
        seq[i] = 0;

    protect_memory(get_enclave_base(), get_enclave_size());
    getchar();
    /*
    mprotect(GET_PFN(modpow_pt), 4096, PROT_NONE);
    mprotect(GET_PFN(sq_pt), 4096, PROT_NONE);
    mprotect(GET_PFN(mul_pt), 4096, PROT_NONE);
    */
    SGX_ASSERT_E( ecall_rsa_decode(eid, &plain, cipher) );
    printf("key is %s\n", seq);
    printf("pagefaults: %d\n", fault_fired);


    info_event("destroying SGX enclave");
    SGX_ASSERT_E( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}
