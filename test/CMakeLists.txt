set(NIST_FLAGS "-march=native -mtune=native -Og -fomit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -D_GNU_SOURCE -Wall -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer ${NIST_FLAGS}")

include_directories(../src)

set(salrs_sources
        ../src/salrs_main.c
        ../src/salrs_main_scheme.c
        ../src/check_salrs.c
        ../src/generating.c
        ../src/packing_salrs.c
        ../src/poly_calculations_salrs.c)

set(salrs_headers
        ../src/salrs_main.h
        ../src/check_salrs.h
        ../src/generating.h
        ../src/packing_salrs.h
        ../src/poly_calculations_salrs.h
        ../src/params_salrs.h
        ../src/polyvec_salrs.h
        ../src/hash_func.h)

set(kyber_headers
        ${salrs_headers}
        ../src/kyber_all.h
        ../src/params_kyber.h
        ../src/api_kyber.h)
set(kyber_sources
        ${salrs_sources}
        ../src/kyber_all.c)

set(keccak_headers
        ${kyber_headers}
        ../src/fips202.h)
set(keccak_sources
        ${kyber_sources}
        ../src/fips202.c)

add_executable(salrs_test
        ${keccak_headers}
        ${keccak_sources}
        ../src/cpucycles.h
        ../src/cpucycles.c
        speed.h
        speed.c
        test_salrs.c
        )

target_link_libraries(salrs_test
        PUBLIC
            salrs)

add_test(
        NAME    salrs_test
        COMMAND salrs_test
)
