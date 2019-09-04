#ifndef SALRS_MAIN_SCHEME_H
#define SALRS_MAIN_SCHEME_H
#include <stdint.h>
#include "kyber_all.h"
#include "randombytes.h"
#include "params_salrs.h"
#include "fips202.h"
#include "polyvec_salrs.h"
#include "generating.h"
#include "poly_calculations_salrs.h"
#include "packing_salrs.h"
#include "params_kyber.h"
#include "check_salrs.h"

void setup_scheme();
void master_key_gen_scheme(unsigned char *mpk, unsigned char *msk);
void derived_public_key_gen_scheme(unsigned char* mpk, unsigned char* dpk);
int derived_public_key_owner_check_scheme(unsigned char *dpk, unsigned char *msk, unsigned char *mpk);
int derived_public_key_public_check_scheme(unsigned char *dpk);
int sign_salrs_scheme(unsigned char *m, unsigned int len, unsigned char (*Ring)[SIZE_DPK],unsigned int r, unsigned char *dpk, unsigned char* mpk, unsigned char *msk, unsigned char *sig);
int verify_salrs_scheme(unsigned char*m, unsigned int len,unsigned char (*Ring)[SIZE_DPK], unsigned int r, unsigned char* sig);
int link_salrs_scheme(unsigned char *sig1, unsigned char*m1, unsigned int len1,
unsigned char (*Ring1)[SIZE_DPK],unsigned int r1,
	unsigned char *sig2, unsigned char*m2, unsigned int len2,
unsigned char (*Ring2)[SIZE_DPK],unsigned int r2);

#endif // SALRS_MAIN_SCHEME.H

#pragma once
