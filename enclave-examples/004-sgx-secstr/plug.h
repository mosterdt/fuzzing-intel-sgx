#define ENCLAVE_SO "../enclave-examples/004-sgx-secstr/Enclave/encl.so"


void call_encl_f(int eid);
void setup_plug(int eid, int e_size, void *e_start);
