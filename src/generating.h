#ifndef  GENERATING_H
#define GENERATING_H

#include <stdint.h>
#include "params_salrs.h"
#include "kyber_all.h"
#include "polyvec_salrs.h"


void poly_uniform(poly *a,
        const unsigned char seed[SEEDBYTES],
	uint16_t nonce);
void poly_uniform_eta(poly *a,
	const unsigned char seed[ETASEEDBYTES],
	uint16_t nonce);
void poly_uniform_gamma(poly *a,
	const unsigned char seed[GAMMASEEDSIZE],
	uint16_t nonce);
void poly_uniform_gmte(poly *a,
	const unsigned char seed[GMTESEEDSIZE],
	uint16_t nonce);
void expand_matA(polyvecl matA[K]);
void expand_V(unsigned char Kyber_k[KYBER_SYMBYTES], polyvecl *V);
void generate_L_eta(polyvecl *s);
void generate_L_gamma(polyvecl *s);
void generate_L_gamma_sub_to_theta_eta(polyvecl *s);
void Hm(polyveck *t, polyvecl H[M]);
void H_theta(unsigned char * m,
	unsigned int mlen,
	unsigned char (*Ring)[SIZE_DPK],
	unsigned int r,
	polyveck *w,
	polyvecm *v,
	polyvecm *I,
	poly* c);

#endif // ! GENERATING.H

#pragma once
