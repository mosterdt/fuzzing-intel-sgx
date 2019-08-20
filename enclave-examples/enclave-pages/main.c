/* utility headers */
#include "debug.h"
#include "cacheutils.h"

/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "Enclave/encl_u.h"


void ocall_print(const char *str)
{
    info("ocall_print: enclave says: '%s'", str);
}


sgx_enclave_id_t create_enclave(void)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_enclave_id_t eid = -1;

    info_event("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave( "./Enclave/encl.so", /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );

    return eid;
}


int main( int argc, char **argv )
{
    int rv = 1;
    sgx_enclave_id_t eid = create_enclave();

    SGX_ASSERT( ecall_dummy(eid, &rv, 1) );

    char buf[80];
    fgets(buf, 80, stdin);
    
    void *sec_p;

    SGX_ASSERT( get_secret_pointer(eid, &sec_p) );
    printf("secret pointer %p\n", sec_p);

    flush(sec_p);


    SGX_ASSERT( ecall_dummy(eid, &rv, 1) );

    segfault_p(eid, &rv, (int *)0x1);


    info_event("destroying SGX enclave");
    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}
