#ifndef POLYVEC_SALRS_H
#define POLYVEC_SALRS_H

#include "params_salrs.h"

typedef struct {
	long long coeffs[N];
} poly;

typedef struct {
	poly vec[L];
} polyvecl;

typedef struct {
	poly vec[K];
} polyveck;

//note that M = 1, although polyvecm here equals to poly, we still define a struct for polyvecm
typedef struct {
	poly vec[M];
} polyvecm;

typedef struct {
	long long coeffs[8];
} poly_8;


#endif // !POLYVEC_SALRS.H

