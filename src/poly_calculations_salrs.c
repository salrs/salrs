#include "polyvec_salrs.h"
#include "poly_calculations_salrs.h"
#include "params_salrs.h"

/*************************************************
* Name:        reduce
*
* Description: For an element a, compute and output
*              r = a mod¡À q.
*
* Arguments:   - long long int a: element a
*
* Returns r.
**************************************************/
long long reduce(long long a)
{
	long long tmp;
	tmp = a % Q;
	if (tmp > Q_2) { tmp -= Q; }
	if (tmp < -Q_2) { tmp += Q; }
	return tmp;
}

/*************************************************
* Name:        poly_addition
*
* Description: addition of polynomials.
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - poly *a: pointer to first input polynomial
*              - poly *b: pointer to second input polynomial
*              - poly *c: pointer to output polynomial
**************************************************/
void poly_addition(poly *a, poly *b, poly *c)
{
	int i;
	for (i = 0; i < N; ++i)
	{
		c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
		c->coeffs[i] = reduce(c->coeffs[i]);
	}
}


/*************************************************
* Name:        poly_substraction
*
* Description: substraction of polynomials.
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - poly *a: pointer to first input polynomial
*              - poly *b: pointer to second input polynomial
*              - poly *c: pointer to output polynomial
**************************************************/
void poly_substraction(poly *a, poly *b, poly *c)
{
	int i;
	for (i = 0; i < N; ++i)
	{
		c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
		c->coeffs[i] = reduce(c->coeffs[i]);
	}
}


/*************************************************
* Name:        big_number_multiplication
*
* Description: multiplication of big numbers
*             (especially for those whose product is bigger than 2^64).
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - long long a: pointer to first input number
*              - long long b: pointer to second input number

**************************************************/
long long big_number_multiplication(long long a, long long b)
{
	long long tmp1[30];
	int count1 = 0, count2 = 0;
	int i;

	long long t1, t2, t3, t4, ans = 0;
	//	printf("\n%lld\n%lld\n%lld\n%lld\n", a, b, -a, -b);
	if (a < 0) { t1 = -a; }
	else { t1 = a; }
	if (b < 0) { t2 = -b; }
	else { t2 = b; }
	t3 = t1;
	t4 = t2;
	while (t1 != 0)
	{
		count1++;
		t1 = t1 / 10;
	}
	while (t2 != 0)
	{
		count2++;
		t2 = t2 / 10;
	}
	if (count1 + count2 <= 18)
	{
		return reduce(a * b);
	}
	else
	{
		for (i = 0; i < 30; ++i)
		{
			tmp1[i] = 0;
		}
		t1 = t3 % 100000;
		t2 = t3 / 100000;
		t1 = t4 * t1;
		t2 = t4 * t2;
		count1 = 0;
		while (t1 != 0)
		{
			tmp1[count1] = t1 % 10;
			count1++;
			t1 = t1 / 10;
		}
		count1 = 5;
		while (t2 != 0)
		{
			tmp1[count1] += t2 % 10;
			count1++;
			t2 = t2 / 10;
		}
	}
	//		for (i = 0; i < 30; ++i)
	//		{
	//		    printf("%lld ", tmp1[i]);
	//		}
	//		printf("\n");

	//mod Q
	for (i = 25; i >= 0; --i)
	{
		ans = (ans * 10 + tmp1[i]) % Q;
	}
	//	}
	if ((a < 0 && b > 0) || (a > 0 && b < 0)) { return (-ans); }
	return ans;
}


/*************************************************
* Name:        poly_num_mul_poly
*
* Description: polynomials multiply with numbers.
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - poly *a: pointer to input polynomial
*              - long long *b: pointer to input number
*              - poly *c: pointer to output polynomial
**************************************************/
void poly_num_mul_poly(poly *a, long long b, poly *c)
{
	int i;
	for (i = 0; i < N; ++i)
	{
		c->coeffs[i] = big_number_multiplication(a->coeffs[i], b);
		c->coeffs[i] = reduce(c->coeffs[i]);
	}
}

/*************************************************
* Name:        poly_mod_one
*
* Description: a big poly mod (x^n - r0) into one small poly
*              used for poly_multiplication
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments    - long long r0: the root
*              - long long n; degree of a
*              - poly *a: pointer input and output polynomial

**************************************************/
void poly_mod_one(long long r0, long long n, poly *a)
{
	int i;
	if (n == 32)
	{
		for (i = 0; i < 32; ++i)
		{
			a->coeffs[i] += big_number_multiplication(a->coeffs[i + 32], r0);
			a->coeffs[i] = reduce(a->coeffs[i]);
		}
	}
}

/*************************************************
* Name:        poly_mul_normal_sixteen
*
* Description: the normal version of multiplication of polynomials of degree sixteen
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - poly *a: pointer to first input polynomial
*              - poly *b: pointer to second input polynomial
*              - poly *c: pointer to output polynomial

**************************************************/
void poly_mul_normal_sixteen(poly *a, poly *b, poly *c)
{
	int m, i, j;
	for (i = 0; i < N; ++i)
	{
		c->coeffs[i] = 0;
	}
	for (i = 0; i < 16; ++i)
	{
		for (j = 0; j < 16; ++j)
		{
			m = i + j;
			c->coeffs[m] += big_number_multiplication(a->coeffs[i], b->coeffs[j]);
			c->coeffs[m] = reduce(c->coeffs[m]);
		}
	}
}

/*************************************************
* Name:        poly_mod_eight
*
* Description: a big poly mod (x^32 - r0) ~ (x^32 - r7) into eight small poly
*              used for poly_multiplication
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - poly *a: pointer to input polynomial
*              - poly *b: pointer to first output polynomial
*              - poly *c: pointer to second output polynomial
*              - long long r0: one of the root
*              - long long r1: one of the root
*              - long long n; degree of a

**************************************************/
void poly_mod_eight(poly *a, poly *a_111, poly *a_112, poly *a_121, poly *a_122,
	poly *a_211, poly *a_212, poly *a_221, poly *a_222)
{
	long long tmp, i;
	poly a_1, a_2, a_11, a_12, a_21, a_22;
	for (i = 0; i < N; ++i)
	{
		a_1.coeffs[i] = 0;
		a_2.coeffs[i] = 0;
		a_11.coeffs[i] = 0;
		a_12.coeffs[i] = 0;
		a_21.coeffs[i] = 0;
		a_22.coeffs[i] = 0;
	}
	for (i = 0; i < N / 2; ++i)
	{
		tmp = big_number_multiplication(a->coeffs[i + N / 2], -R4);
		a_1.coeffs[i] = a->coeffs[i] + tmp;
		a_1.coeffs[i] = reduce(a_1.coeffs[i]);
		a_2.coeffs[i] = a->coeffs[i] - tmp;
		a_2.coeffs[i] = reduce(a_2.coeffs[i]);
	}

	for (i = 0; i < N / 4; ++i)
	{
		tmp = big_number_multiplication(a_1.coeffs[i + N / 4], -R6);
		a_11.coeffs[i] = a_1.coeffs[i] + tmp;
		a_11.coeffs[i] = reduce(a_11.coeffs[i]);
		a_12.coeffs[i] = a_1.coeffs[i] - tmp;
		a_12.coeffs[i] = reduce(a_12.coeffs[i]);
	}

	for (i = 0; i < N / 4; ++i)
	{
		tmp = big_number_multiplication(a_2.coeffs[i + N / 4], -R2);
		a_21.coeffs[i] = a_2.coeffs[i] + tmp;
		a_21.coeffs[i] = reduce(a_21.coeffs[i]);
		a_22.coeffs[i] = a_2.coeffs[i] - tmp;
		a_22.coeffs[i] = reduce(a_22.coeffs[i]);
	}

	for (i = 0; i < N / 8; ++i)
	{
		tmp = big_number_multiplication(a_11.coeffs[i + N / 8], -R7);
		a_111->coeffs[i] = a_11.coeffs[i] + tmp;
		a_111->coeffs[i] = reduce(a_111->coeffs[i]);
		a_112->coeffs[i] = a_11.coeffs[i] - tmp;
		a_112->coeffs[i] = reduce(a_112->coeffs[i]);
	}

	for (i = 0; i < N / 8; ++i)
	{
		tmp = big_number_multiplication(a_12.coeffs[i + N / 8], -R3);
		a_121->coeffs[i] = a_12.coeffs[i] + tmp;
		a_121->coeffs[i] = reduce(a_121->coeffs[i]);
		a_122->coeffs[i] = a_12.coeffs[i] - tmp;
		a_122->coeffs[i] = reduce(a_122->coeffs[i]);
	}

	for (i = 0; i < N / 8; ++i)
	{
		tmp = big_number_multiplication(a_21.coeffs[i + N / 8], -R5);
		a_211->coeffs[i] = a_21.coeffs[i] + tmp;
		a_211->coeffs[i] = reduce(a_211->coeffs[i]);
		a_212->coeffs[i] = a_21.coeffs[i] - tmp;
		a_212->coeffs[i] = reduce(a_212->coeffs[i]);
	}

	for (i = 0; i < N / 8; ++i)
	{
		tmp = big_number_multiplication(a_22.coeffs[i + N / 8], -R1);
		a_221->coeffs[i] = a_22.coeffs[i] + tmp;
		a_221->coeffs[i] = reduce(a_221->coeffs[i]);
		a_222->coeffs[i] = a_22.coeffs[i] - tmp;
		a_222->coeffs[i] = reduce(a_222->coeffs[i]);
	}
}


/*************************************************
* Name:        poly_mul_karatsuba
*
* Description: multiplication of small polynomials, the degree of which is 32, 
*               using karatsuba.
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - poly *a: pointer to first input polynomial
*              - poly *b: pointer to second input polynomial
*              - poly *c: pointer to output polynomial

**************************************************/
void poly_mul_karatsuba(poly *a, poly *b, poly *c)
{
	poly a0, a1, b0, b1;
	int i;
	//here we have a0 = F0, a1 = F1, b0 = G0, b1 = G1;
	for (i = 0; i < 16; ++i)
	{
		a0.coeffs[i] = a->coeffs[i];
		a1.coeffs[i] = a->coeffs[i + 16];
		b0.coeffs[i] = b->coeffs[i];
		b1.coeffs[i] = b->coeffs[i + 16];
	}

	poly a0b0, a1b1, a0a1, b0b1, tmp1, tmp2;
	poly_mul_normal_sixteen(&a0, &b0, &a0b0);
	poly_mul_normal_sixteen(&a1, &b1, &a1b1);


	for (i = 32; i >= 0; --i)
	{
		a1b1.coeffs[i + 16] = a1b1.coeffs[i];
	}
	for (i = 0; i < 16; ++i)
	{
		a1b1.coeffs[i] = 0;
	}

	poly_substraction(&a0b0, &a1b1, &tmp1);

	//todo (1 - x^16)(F0G0 - x^16F1G1) where tmp1 = (F0G0 - x^16F1G1)
	poly tmp3, tmp4;
	for (i = 0; i < N; ++i)
	{
		tmp3.coeffs[i] = 0;
	}
	for (i = 48; i >= 0; --i)
	{
		tmp3.coeffs[i + 16] = tmp1.coeffs[i];
	}
	poly_substraction(&tmp1, &tmp3, &tmp4);
	//end todo

	poly_addition(&a0, &a1, &a0a1);
	poly_addition(&b0, &b1, &b0b1);

	poly_mul_normal_sixteen(&a0a1, &b0b1, &tmp2);
	for (i = 32; i >= 0; --i)
	{
		tmp2.coeffs[i + 16] = tmp2.coeffs[i];
	}
	for (i = 0; i < 16; ++i)
	{
		tmp2.coeffs[i] = 0;
	}

	poly_addition(&tmp4, &tmp2, c);
}

/*************************************************
* Name:        poly_multiplication
*
* Description: multiplication of polynomials using partially-splitting mathod
*              every element in the output polynomial should
*              call reduce() to map into (-q/2, q/2)
* Arguments:    - poly *a: pointer to first input polynomial
*              - poly *b: pointer to second input polynomial
*              - poly *c: pointer to output polynomial

**************************************************/
void poly_multiplication(poly *a, poly *b, poly *c)
{
	int i;
	poly a_111, a_112, a_121, a_122, a_211, a_212, a_221, a_222;
	poly b_111, b_112, b_121, b_122, b_211, b_212, b_221, b_222;
	poly c_111, c_112, c_121, c_122, c_211, c_212, c_221, c_222;
	poly c_11, c_12, c_21, c_22, c_1, c_2;

	poly_mod_eight(a, &a_111, &a_112, &a_121, &a_122, &a_211, &a_212, &a_221, &a_222);
	poly_mod_eight(b, &b_111, &b_112, &b_121, &b_122, &b_211, &b_212, &b_221, &b_222);

	poly_mul_karatsuba(&a_111, &b_111, &c_111);
	poly_mul_karatsuba(&a_112, &b_112, &c_112);
	poly_mul_karatsuba(&a_121, &b_121, &c_121);
	poly_mul_karatsuba(&a_122, &b_122, &c_122);
	poly_mul_karatsuba(&a_211, &b_211, &c_211);
	poly_mul_karatsuba(&a_212, &b_212, &c_212);
	poly_mul_karatsuba(&a_221, &b_221, &c_221);
	poly_mul_karatsuba(&a_222, &b_222, &c_222);

	for (i = 0; i < 32; ++i)
	{
		c_111.coeffs[i] -= reduce(big_number_multiplication((c_111.coeffs[i + 32]), R7));
		c_111.coeffs[i] = reduce(c_111.coeffs[i]);
	}
	for (i = 0; i < 32; ++i)
	{
		c_112.coeffs[i] += reduce(big_number_multiplication((c_112.coeffs[i + 32]), R7));
		c_112.coeffs[i] = reduce(c_112.coeffs[i]);
	}
	for (i = 0; i < 32; ++i)
	{
		c_121.coeffs[i] -= reduce(big_number_multiplication((c_121.coeffs[i + 32]), R3));
		c_121.coeffs[i] = reduce(c_121.coeffs[i]);
	}
	for (i = 0; i < 32; ++i)
	{
		c_122.coeffs[i] += reduce(big_number_multiplication((c_122.coeffs[i + 32]), R3));
		c_122.coeffs[i] = reduce(c_122.coeffs[i]);
	}
	for (i = 0; i < 32; ++i)
	{
		c_211.coeffs[i] -= reduce(big_number_multiplication((c_211.coeffs[i + 32]), R5));
		c_211.coeffs[i] = reduce(c_211.coeffs[i]);
	}
	for (i = 0; i < 32; ++i)
	{
		c_212.coeffs[i] += reduce(big_number_multiplication((c_212.coeffs[i + 32]), R5));
		c_212.coeffs[i] = reduce(c_212.coeffs[i]);
	}
	for (i = 0; i < 32; ++i)
	{
		c_221.coeffs[i] -= reduce(big_number_multiplication((c_221.coeffs[i + 32]), R1));
		c_221.coeffs[i] = reduce(c_221.coeffs[i]);
	}
	for (i = 0; i < 32; ++i)
	{
		c_222.coeffs[i] += reduce(big_number_multiplication((c_222.coeffs[i + 32]), R1));
		c_222.coeffs[i] = reduce(c_222.coeffs[i]);
	}

	for (i = 0; i < 32; ++i)
	{
		c_111.coeffs[i + 32] = c_111.coeffs[i];
		c_111.coeffs[i] = reduce(big_number_multiplication(c_111.coeffs[i], (-R7)));
		c_112.coeffs[i + 32] = c_112.coeffs[i];
		c_112.coeffs[i] = reduce(big_number_multiplication(c_112.coeffs[i], (R7)));
		c_121.coeffs[i + 32] = c_121.coeffs[i];
		c_121.coeffs[i] = reduce(big_number_multiplication(c_121.coeffs[i], (-R3)));
		c_122.coeffs[i + 32] = c_122.coeffs[i];
		c_122.coeffs[i] = reduce(big_number_multiplication(c_122.coeffs[i], (R3)));
		c_211.coeffs[i + 32] = c_211.coeffs[i];
		c_211.coeffs[i] = reduce(big_number_multiplication(c_211.coeffs[i], (-R5)));
		c_212.coeffs[i + 32] = c_212.coeffs[i];
		c_212.coeffs[i] = reduce(big_number_multiplication(c_212.coeffs[i], (R5)));
		c_221.coeffs[i + 32] = c_221.coeffs[i];
		c_221.coeffs[i] = reduce(big_number_multiplication(c_221.coeffs[i], (-R1)));
		c_222.coeffs[i + 32] = c_222.coeffs[i];
		c_222.coeffs[i] = reduce(big_number_multiplication(c_222.coeffs[i], (R1)));
	}

	poly_substraction(&c_111, &c_112, &c_11);
	poly_substraction(&c_121, &c_122, &c_12);
	poly_substraction(&c_211, &c_212, &c_21);
	poly_substraction(&c_221, &c_222, &c_22);

	for (i = 0; i < 64; ++i)
	{
		c_11.coeffs[i] = reduce(big_number_multiplication(c_11.coeffs[i], reduce(big_number_multiplication(((Q + 1) / 2), R1))));
		c_12.coeffs[i] = reduce(big_number_multiplication(c_12.coeffs[i], reduce(big_number_multiplication(((Q + 1) / 2), R5))));
		c_21.coeffs[i] = reduce(big_number_multiplication(c_21.coeffs[i], reduce(big_number_multiplication(((Q + 1) / 2), R3))));
		c_22.coeffs[i] = reduce(big_number_multiplication(c_22.coeffs[i], reduce(big_number_multiplication(((Q + 1) / 2), R7))));
	}

	for (i = 0; i < 64; ++i)
	{
		c_11.coeffs[i + 64] = c_11.coeffs[i];
		c_11.coeffs[i] = reduce(big_number_multiplication(c_11.coeffs[i], (-R6)));
		c_12.coeffs[i + 64] = c_12.coeffs[i];
		c_12.coeffs[i] = reduce(big_number_multiplication(c_12.coeffs[i], (R6)));
		c_21.coeffs[i + 64] = c_21.coeffs[i];
		c_21.coeffs[i] = reduce(big_number_multiplication(c_21.coeffs[i], (-R2)));
		c_22.coeffs[i + 64] = c_22.coeffs[i];
		c_22.coeffs[i] = reduce(big_number_multiplication(c_22.coeffs[i], (R2)));
	}
	poly_substraction(&c_11, &c_12, &c_1);
	poly_substraction(&c_21, &c_22, &c_2);

	for (i = 0; i < 128; ++i)
	{
		c_1.coeffs[i] = reduce(big_number_multiplication(c_1.coeffs[i], reduce(big_number_multiplication(((Q + 1) / 2), R2))));
		c_2.coeffs[i] = reduce(big_number_multiplication(c_2.coeffs[i], reduce(big_number_multiplication(((Q + 1) / 2), R6))));
	}

	for (i = 0; i < 128; ++i)
	{
		c_1.coeffs[i + 128] = c_1.coeffs[i];
		c_1.coeffs[i] = reduce(big_number_multiplication(c_1.coeffs[i], (-R4)));
		c_2.coeffs[i + 128] = c_2.coeffs[i];
		c_2.coeffs[i] = reduce(big_number_multiplication(c_2.coeffs[i], (R4)));
	}
	poly_substraction(&c_1, &c_2, c);
	for (i = 0; i < N; ++i)
	{
		c->coeffs[i] = reduce(big_number_multiplication(c->coeffs[i], reduce(big_number_multiplication(((Q + 1) / 2), R4))));
	}
}

