#ifndef POLY_CALCULATIONS_SALRS_H
#define POLY_CALCUALTIONS_SALRS_H

#include "kyber_all.h"
#include "polyvec_salrs.h"

long long reduce(long long a);

long long big_number_multiplication(long long a, long long b);

void poly_multiplication(poly *a, poly *b, poly *c);

void poly_addition(poly *a, poly *b, poly *c);

void poly_substraction(poly *a, poly *b, poly *c);

void poly_mod_one(long long r0, long long n, poly *a);

void poly_mul_normal_sixteen(poly *a, poly *b, poly *c);

void poly_mod_eight(poly *a, poly *a_111, poly *a_112, poly *a_121, poly *a_122,
	poly *a_211, poly *a_212, poly *a_221, poly *a_222);

void poly_mul_karatsuba(poly *a, poly *b, poly *c);


#endif // !POLY_CALCULATIONS_SALRS.H

#pragma once
