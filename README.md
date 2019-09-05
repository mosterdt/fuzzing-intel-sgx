# Intel SGX Enclave Fuzzer

This code was used in the [`Fuzzing Intel SGX Enclaves`](https://u.debacker.me/Thomas_De_BackerFuzzing_Intel_SGX_enclaves.pdf) masterthesis.

## Installation
* Get the Intel SGX SDK.
* Get and install the Intel SGX Linux kernel driver. (`# insmod isgx.ko`)
* Get and install the [SGX-Step](https://github.com/jovanbulck/sgx-step) driver. (`# make load`)

## Usage
You can try the demo in the root directory. Things are a bit unstable and messy, and this is unlikely to change in the future. If anyone has any questions, feel free to ask them.

## 
The examples in the `enclave-examples` are based on the [jovanbulck/sgx-tutorial-space18](https://github.com/jovanbulck/sgx-tutorial-space18) repository exercises.

## License
This code is free software licenced under GPLv3 and based on the great work by Jo Van Bulck on [SGX-Step](https://github.com/jovanbulck/sgx-step) and [jovanbulck/sgx-tutorial-space18](https://github.com/jovanbulck/sgx-tutorial-space18).
