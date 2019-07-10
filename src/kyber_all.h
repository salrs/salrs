#ifndef KYBER_ALL_H
#define KYBER_ALL_H

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "params_kyber.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE  72
#define _GNU_SOURCE

/*
* Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
* coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
*/
typedef struct {
	uint16_t coeffs[KYBER_N];
} poly_kyber;

typedef struct {
	poly_kyber vec[KYBER_K];
} polyvec_kyber;

void shake128_absorb_kyber(uint64_t *s, const unsigned char *input, unsigned int inputByteLen);
void shake128_squeezeblocks_kyber(unsigned char *output, unsigned long long nblocks, uint64_t *s);

void shake256_kyber(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);
void sha3_256_kyber(unsigned char *output, const unsigned char *input,  unsigned long long inlen);
void sha3_512_kyber(unsigned char *output, const unsigned char *input,  unsigned long long inlen);

int verify_kyber(const unsigned char *a, const unsigned char *b, size_t len);

void cmov_kyber(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);
void randombytes_kyber(unsigned char *x, size_t xlen);
uint16_t freeze_kyber(uint16_t x);

uint16_t montgomery_reduce_kyber(uint32_t a);

uint16_t barrett_reduce_kyber(uint16_t a);
void ntt_kyber(uint16_t* poly_kyber);
void invntt_kyber(uint16_t* poly_kyber);

void cbd_kyber(poly_kyber *r, const unsigned char *buf);
void polyvec_compress_kyber(unsigned char *r, const polyvec_kyber *a);
void polyvec_decompress_kyber(polyvec_kyber *r, const unsigned char *a);

void polyvec_tobytes_kyber(unsigned char *r, const polyvec_kyber *a);
void polyvec_frombytes_kyber(polyvec_kyber *r, const unsigned char *a);

void polyvec_ntt_kyber(polyvec_kyber *r);
void polyvec_invntt_kyber(polyvec_kyber *r);

void polyvec_pointwise_acc_kyber(poly_kyber *r, const polyvec_kyber *a, const polyvec_kyber *b);

void polyvec_add_kyber(polyvec_kyber *r, const polyvec_kyber *a, const polyvec_kyber *b);
void poly_compress_kyber(unsigned char *r, const poly_kyber *a);
void poly_decompress_kyber(poly_kyber *r, const unsigned char *a);

void poly_tobytes_kyber(unsigned char *r, const poly_kyber *a);
void poly_frombytes_kyber(poly_kyber *r, const unsigned char *a);

void poly_frommsg_kyber(poly_kyber *r, const unsigned char msg[KYBER_SYMBYTES]);
void poly_tomsg_kyber(unsigned char msg[KYBER_SYMBYTES], const poly_kyber *r);

void poly_getnoise_kyber(poly_kyber *r, const unsigned char *seed, unsigned char nonce);

void poly_ntt_kyber(poly_kyber *r);
void poly_invntt_kyber(poly_kyber *r);

void poly_add_kyber(poly_kyber *r, const poly_kyber *a, const poly_kyber *b);
void poly_sub_kyber(poly_kyber *r, const poly_kyber *a, const poly_kyber *b);
void indcpa_publicseed_kyber(unsigned char *buf);

void indcpa_keypair_kyber(unsigned char *pk,
	unsigned char *sk);

void indcpa_enc_kyber(unsigned char *c,
	const unsigned char *m,
	const unsigned char *pk,
	const unsigned char *coins);

void indcpa_dec_kyber(unsigned char *m,
	const unsigned char *c,
	const unsigned char *sk);

int crypto_kem_keypair_kyber(unsigned char *pk,
	unsigned char *sk);

int crypto_kem_enc_kyber(unsigned char *ct,
	unsigned char *ss,
	const unsigned char *pk);

int crypto_kem_dec_kyber(unsigned char *ss,
	const unsigned char *ct,
	const unsigned char *sk);


#endif // !KYBER_ALL.H

#pragma once
