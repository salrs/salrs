#ifndef CHECK_SALRS_H
#define CHECK_SALRS_H

#include "kyber_all.h"
#include "params_salrs.h"
#include "polyvec_salrs.h"

int check_t_norm(polyveck *t);
int check_z_norm(polyvecl *z);
int check_c(poly *c);
int equal_c(poly *c1, poly* c2);
int equal_I(polyvecm *I1, polyvecm* I2);



#endif // !CHECK_SALRS.H

#pragma once
