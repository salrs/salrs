# salrs
A crypto repository for Linkable Ring Signature with Stealth Addresses

# Installation Requirements

## Environment

* aystem requirements : Linux
* headers included from C standard library: `stdint.h`, `assert.h`, `string.h`, `stdio.h`, `sys/types.h`, `errno.h`, `sys/stat.h`, `fcntl.h`, `inttypes.h`.
* headers included from Linux standard library: `unistd.h`, `sys/syscall.h`.

## Build and Test
To download, build and run the test, follow the following steps:

```
git clone https://github.com/salrs/salrs.git
cd salrs/test && make
./test_salrs
``` 


# Details of Test

`test_salrs` tests:
* average, median, maximum and minimum runtime of 1000 times of `setup()`;
* average, median, maximum and minimum runtime of 1000 times of `master_key_gen()`, which is used to generate (MPK, MSK) pairs;
* average, median, maximum and minimum runtime of 1000 times of `derived_public_key_gen()`,`derived_public_key_owner_check()` and `derived_public_key_public_check()`, unless some checks fail and failures are reported.
* average, median, maximum and minimum runtime of 1000 times of `sign_salrs()` and `verify_salrs()` with ring size 1, 3, 5, 10, 20, unless some signing or verifying fail and failures are reported.
* average, maximum and minimum times of rejection in `sign_salrs()` tested above.


# Introduction of Source Files

## Third party libraries
* `fips202.c` and `fips202.h`: sha3-keccak function
* `params_kyber.h`: parameters of kyber
* `api_kyber.h`: api of three main functions in kyber
* `kyber_all.c` and `kyber_all.h`: all functions of kyber

## Files of salrs
* `params_salrs.h`: parameters of salrs
* `polyvec_salrs.h`: definitions of struct used in salrs
* `randombytes.c` and `randombytes.h`: functions used to generate random numbers
* `check_salrs.c` and `check_salrs.h`: norm and equality checking functions of salrs
* `generating.c` and `generating.h`: functions that generating vectors and matrices of salrs
* `packing_salrs.c` and `packing_salrs.h`: packing and unpacking functions of salrs
* `poly_calculations_salrs.c` and `poly_calculations_salrs.h`: poly calculation functions of salrs
* `salrs_main.c` and `salrs_main.h`: main functions introduced in salrs 

## Files of test
* `cpucycles.c` and `cpucycles.h`: functions used to record cpucycles
* `speed.c` and `speed.h`: functions used to calculate the speed
* `test_salrs.c`: test of main functions in `salrs_main.c`

