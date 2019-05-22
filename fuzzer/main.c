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
int working_window = 3;
int loop_detection_c = 0;
int progress_c= 0;

#define SEQ_LEN 100
void *seq[SEQ_LEN];


gprsgx_region_t get_enclave_regs(void) {
    gprsgx_region_t gprsgx;
    edbgrd(get_enclave_ssa_gprsgx_adrs(), &gprsgx, sizeof(gprsgx_region_t));
    return gprsgx;

}

void print_working_set(void **seq, int window) {
    uint64_t *pte = NULL;
    for (int i=0; i <= window; i++) {
        void *seq_address = seq[(fault_fired - window + i) % SEQ_LEN];
        int offset =  (seq_address - ebase_address) >> 12;
        pte = remap_page_table_level(seq_address, PTE);
        printf("%d=%d ", offset, DIRTY(*pte)*2 + ACCESSED(*pte));
        //print_pte_adrs(GET_PFN(seq_address));
        //print_pte(pte);
    };
    printf("\n");
    
}

int detect_loop(void *curr_adrs, int window) {
    if (seq[(fault_fired-window-1) % SEQ_LEN] == curr_adrs) {
        loop_detection_c++;
    } else {
        loop_detection_c = 0;
    }
    if (loop_detection_c > 100) {
        loop_detection_c = 0;
        return 1;
    } else {
        return 0;
    }
}

int detect_progress() {
    return (working_window == 4 && loop_detection_c > 30);

    if (loop_detection_c > 40) {
        progress_c++;
    }
    if (progress_c > 3) {
        progress_c = 0;
        return 1;
    } else {
        return 0;
    }
}


void fault_handler(void *base_adrs)
{
    fault_fired++;
    mprotect(GET_PFN(seq[(fault_fired-working_window)%SEQ_LEN]), 4096, PROT_NONE);
    seq[fault_fired %SEQ_LEN] = base_adrs;
    mprotect(GET_PFN(base_adrs), 4096, PROT_WRITE|PROT_READ|PROT_EXEC);

    if (detect_loop(base_adrs, working_window)){
        working_window++;
    }
    /*
    if (detect_progress()) {
        working_window = (2 > working_window-1 ? 2 : working_window-1);
        mprotect(GET_PFN(seq[(fault_fired-working_window)%SEQ_LEN]), 4096, PROT_NONE);
    }
    */

    if (ebase_address <= base_adrs && base_adrs <= ebase_address + enc_size) {
        gprsgx_region_t regs = get_enclave_regs();

        int p_offset = (base_adrs - ebase_address) >> 12;
        int rip_offset = ((void *)regs.fields.rip - ebase_address);
        int rsp_offset = ((void *)regs.fields.rsp - ebase_address);
        printf("ba=%p, ", base_adrs);
        printf("ff=%d, ", fault_fired);
        printf("rip=%d, ", rip_offset);
        printf("rsp=%d, ", rsp_offset);
        printf("window=%d, ", working_window);
        printf("lpd=%d, ", loop_detection_c);
        printf("offset=%d", p_offset);
        printf("\n");

        if (working_window > 1)
            print_working_set(seq, working_window);
    } else if (base_adrs == NULL) {
        printf("null pointer\n");
        abort();
    } else {
        printf("out enclave: pfn=%p, ba=%p, loc=%d\n",
                GET_PFN(base_adrs), base_adrs, base_adrs - GET_PFN(base_adrs));
    }
    fflush(0);

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

void reset_ww() {
    fault_fired = 0;
    working_window = 1;
    loop_detection_c = 0;

    for (int i=0; i < SEQ_LEN; i++) {
        seq[i] = 0;
    }
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


    fflush(0);
    reset_ww();
    getchar();
    protect_memory(get_enclave_base(), get_enclave_size());
    cipher = rand();
    SGX_ASSERT_E( ecall_rsa_decode(eid, &plain, cipher) );
    printf("pagefaults: %d\n", fault_fired);


    fflush(0);
    reset_ww();
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

    fflush(0);
    reset_ww();
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

