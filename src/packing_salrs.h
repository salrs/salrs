#ifndef PACKING_SALRS_H
#define PACKING_SALRS_H

#include "params_salrs.h"
#include "kyber_all.h"
#include "polyvec_salrs.h"

void pack_polyveck_q(polyveck *t,
	unsigned char *t_char);
void unpack_polyveck_q(unsigned char *t_char,
	polyveck *t);
void pack_polyvecl_eta(polyvecl *s,
	unsigned char *s_char);
void unpack_polyvecl_eta(unsigned char *s_char,
	polyvecl *s);
void pack_polyvecl_gmte(polyvecl *z,
	unsigned char *z_char);
void unpack_polyvecl_gmte(unsigned char *z_char,
	polyvecl *z);
void pack_polyvecm_q(polyvecm *m,
	unsigned char *m_char);
void unpack_polyvecm_q(unsigned char *m_char,
	polyvecm *m);
/**
void pack_i(polyvecm *i,
	unsigned char *i_char);
void unpack_i(unsigned char *i_char,
	polyvecm *i);
**/
void pack_mpk(unsigned char *pkkem,
	polyveck *t,
	unsigned char *mpk);
void unpack_mpk(unsigned char *mpk,
	unsigned char *pkkem,
	polyveck *t);
void pack_msk(unsigned char *skkem,
	polyvecl *s,
	unsigned char *msk);
void unpack_msk(unsigned char *msk,
	unsigned char *skkem,
	polyvecl *s);
void pack_dpk(unsigned char *c,
	polyveck *t,
	unsigned char *dpk);
void unpack_dpk(unsigned char *dpk,
	unsigned char *c,
	polyveck *t);
void pack_sig(poly *c,
	unsigned int r,
	polyvecm* i,
	unsigned char *sig);
int unpack_sig(unsigned char *sig,
	poly *c,
	unsigned int r,
	polyvecm* i);

#endif
