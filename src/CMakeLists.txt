set(NIST_FLAGS "-march=native -mtune=native -Og -fomit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -D_GNU_SOURCE -Wall -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer ${NIST_FLAGS}")

find_package(OpenSSL REQUIRED)

set(salrs_headers
        salrs_main.h salrs_main_scheme.h generating.h packing_salrs.h poly_calculations_salrs.h params_salrs.h  polyvec_salrs.h hash_func.h randombytes.h)
set(salrs_sources
        salrs_main.c salrs_main_scheme.c check_salrs.c generating.c packing_salrs.c poly_calculations_salrs.c randombytes.c)

set(kyber_headers
        ${salrs_headers} kyber_all.h params_kyber.h api_kyber.h)
set(kyber_sources
        ${salrs_sources} kyber_all.c)

set(keccak_headers
        ${kyber_headers} fips202.h)
set(keccak_sources
        ${kyber_sources} fips202.c)

add_library(salrs
        ${keccak_headers}
        ${keccak_sources})

target_link_libraries(salrs OpenSSL::Crypto)
