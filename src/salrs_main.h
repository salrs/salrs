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

void Setup();
void MasterSeedGen(unsigned char *seed);
void MasterKeyGen(unsigned char *seed, unsigned char *MPK, unsigned char *MSVK, unsigned char *MSSK);
int MasterPublicKeyPublicCheck(unsigned char *MPK);
void DerivedPublicKeyGen(unsigned char* MPK, unsigned char* DPK);
int DerivedPublicKeyOwnerCheck(unsigned char *DPK, unsigned char *MPK, unsigned char *MSVK);
int DerivedPublicKeyPublicCheck(unsigned char* DPK);
int Sign(unsigned char *m, unsigned int mlen, unsigned char (*Ring)[SIZE_DPK],unsigned int r, unsigned char *DPK, unsigned char* MPK, unsigned char *MSVK, unsigned char *MSSK, unsigned char *sig, unsigned char *ID);
int Verify(unsigned char *m, unsigned int mlen,unsigned char (*Ring)[SIZE_DPK], unsigned int r, unsigned char* sig, unsigned char *key_image);
int Link(unsigned char *sig1, unsigned char *m1, unsigned int mlen1,
unsigned char (*Ring1)[SIZE_DPK],unsigned int r1,
	unsigned char *sig2, unsigned char *m2, unsigned int mlen2,
unsigned char (*Ring2)[SIZE_DPK],unsigned int r2);

#endif // SALRS_MAIN.H

#pragma once
