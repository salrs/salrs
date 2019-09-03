# salrs
A crypto repository for Linkable Ring Signature with Stealth Addresses

# Installation Requirements

## Environment

* system requirements : Linux
* headers included from C standard library: `stdint.h`, `assert.h`, `string.h`, `stdio.h`, `sys/types.h`, `errno.h`, `sys/stat.h`, `fcntl.h`, `inttypes.h`.
* headers included from Linux standard library: `unistd.h`, `sys/syscall.h`.

## Build and Test
To download, build and run the test in test, follow the following steps:

```
git clone https://github.com/salrs/salrs.git
cd salrs/test && make
./test_salrs
``` 

To run the test in test_scheme, follow the following steps:

```
cd salrs/test_scheme && make
./test_salrs_scheme
``` 


# Details of Test

`test_salrs` tests:
* average, median, maximum and minimum runtime of 1000 times of `Setup()`.
* average, median, maximum and minimum runtime of 1000 times of `MasterKeyGen()`, which is used to generate (MPK, MSK) pairs.
* average, median, maximum and minimum runtime of 1000 times of `DerivedPublicKeyGen()`,`DerivedPublicKeyOwnerCheck()` and `DerivedPublicKeyPublicCheck()`, unless some checks fail and failures are reported.
* average, median, maximum and minimum runtime of 1000 times of `Sign()` and `Verify()` with ring size 1, 3, 5, 10, 20, unless some signing or verifying fail and failures are reported.
* average, maximum and minimum times of rejection in `Sign()` tested above.
* test_salrs is used to test salrs_main.c.
* NOTE: The max available ring size is 40 in our system restricted to the resources we have allocated. The max ring size may change based on the resources allocated.

`test_salrs_scheme` tests:
* average, median, maximum and minimum runtime of 1000 times of `setup_scheme()`.
* average, median, maximum and minimum runtime of 1000 times of `master_key_gen_scheme()`, which is used to generate (MPK, MSK) pairs.
* average, median, maximum and minimum runtime of 1000 times of `derived_public_key_gen_scheme()`,`derived_public_key_owner_check_scheme()` and `derived_public_key_public_check_scheme()`, unless some checks fail and failures are reported.
* average, median, maximum and minimum runtime of 1000 times of `sign_salrs_scheme()` and `verify_salrs_scheme()` with ring size 1, 3, 5, 10, 20, unless some signing or verifying fail and failures are reported.
* average, maximum and minimum times of rejection in `sign_salrs_scheme()` tested above.
* test_salrs_scheme is used to test salrs_main_scheme.c.
* NOTE: The max available ring size is 40 in our system restricted to the resources we have allocated. The max ring size may change based on the resources allocated.

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
* `salrs_main_scheme.c` and `salrs_main_scheme.h`: paper version of main functions introduced in salrs
* `salrs_main.c` and `salrs_main.h`: another version of main functions introduced in salrs (reserved for practical application)
 
## Files of test
* `cpucycles.c` and `cpucycles.h`: functions used to record cpucycles
* `speed.c` and `speed.h`: functions used to calculate the speed
* `test_salrs.c`: test of main functions in `salrs_main.c`
* `test_salrs_scheme.c`: test of main functions in `salrs_main_scheme.c`

