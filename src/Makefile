CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer

NISTFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer

SOURCES = salrs_main.c check_salrs.c generating.c packing_salrs.c poly_calculations_salrs.c
HEADERS = salrs_main.h check_salrs.c generating.h packing_salrs.h poly_calculations_salrs.h \
          params_salrs.h  polyvec_salrs.h hash_func.h

KYBER_SOURCES = $(SOURCES) kyber_all.c
KYBER_HEADERS = $(HEADERS) kyber_all.h params_kyber.h api_kyber.h 

KECCAK_SOURCES = $(KYBER_SOURCES) fips202.c
KECCAK_HEADERS = $(KYBER_HEADERS) fips202.h

all: test/test_salrs

test/test_salrs: test/test_salrs.c randombytes.c test/cpucycles.c \
  test/speed.c $(KECCAK_SOURCES) randombytes.h test/cpucycles.h test/speed.h \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) $< randombytes.c test/cpucycles.c test/speed.c \
	  $(KECCAK_SOURCES) -o $@


.PHONY: clean

clean:
	rm -f *~ test/*~
	rm -f test/test_salrs
