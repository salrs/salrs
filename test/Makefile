CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer

NISTFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer

SOURCES = ../src/salrs_main.c ../src/check_salrs.c ../src/generating.c ../src/packing_salrs.c ../src/poly_calculations_salrs.c
HEADERS = ../src/salrs_main.h ../src/check_salrs.h ../src/generating.h ../src/packing_salrs.h ../src/poly_calculations_salrs.h \
          ../src/params_salrs.h  ../src/polyvec_salrs.h ../src/hash_func.h

KYBER_SOURCES = $(SOURCES) ../src/kyber_all.c
KYBER_HEADERS = $(HEADERS) ../src/kyber_all.h ../src/params_kyber.h ../src/api_kyber.h 

KECCAK_SOURCES = $(KYBER_SOURCES) ../src/fips202.c
KECCAK_HEADERS = $(KYBER_HEADERS) ../src/fips202.h

all: test_salrs

test_salrs: test_salrs.c ../src/randombytes.c ../src/cpucycles.c \
  speed.c $(KECCAK_SOURCES) ../src/randombytes.h ../src/cpucycles.h speed.h \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) $< ../src/randombytes.c ../src/cpucycles.c speed.c \
	  $(KECCAK_SOURCES) -o $@


.PHONY: clean

clean:
	rm -f test_salrs
