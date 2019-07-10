#ifndef SALRS_MAIN_H
#define SALRS_MAIN_H
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

void setup();
void master_key_gen(unsigned char *mpk, unsigned char *msk);
void derived_public_key_gen(unsigned char* mpk, unsigned char* dpk);
int derived_public_key_owner_check(unsigned char *dpk, unsigned char *msk, unsigned char *mpk);
int derived_public_key_public_check(unsigned char *dpk);
int sign_salrs(unsigned char *m, unsigned int len, unsigned char (*Ring)[SIZE_DPK],unsigned int r, unsigned char *dpk, unsigned char* mpk, unsigned char *msk, polyvecl *z, unsigned char *sig);
int verify_salrs(unsigned char*m, unsigned int len,unsigned char (*Ring)[SIZE_DPK], unsigned int r, polyvecl *z, unsigned char* sig);
int link_salrs(unsigned char *sig1, unsigned int r1,polyvecl *z1,
	unsigned char *sig2, unsigned int r2, polyvecl *z2);


#endif // SALRS_MAIN.H

#pragma once
