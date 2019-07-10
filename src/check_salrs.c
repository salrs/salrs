#include "params_salrs.h"
#include "kyber_all.h"
#include "check_salrs.h"
#include "polyvec_salrs.h"


/*************************************************
* Name:        check_t_norm
*
* Description:    a function to check
*              whether the coefficients are in (-q/2, q/2)
*
* Arguments:   - polyveck *t: pointer to input t
*
* Returns 0/1. 1 means belonging to Rkq, 0 means not belonging to Rkq.
**************************************************/
int check_t_norm(polyveck *t)
{
	int i, j;
	for (i = 0; i < K; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if ((t->vec[i].coeffs[j] > Q_2) || (t->vec[i].coeffs[j] < -Q_2))
			{
				return 0;
			}
		}
	}
	return 1;
}

/*************************************************
* Name:        check_z_norm
*
* Description:    a function to check
*              whether the coefficients are in (-gamma_minus_two_theta_eta, gamma_minus_two_theta_eta)
*
* Arguments:   - polyvecl *z: pointer to input z
*
* Returns 0/1. 1 means belonging to S_L_gamma_minus_two_theta_eta, 0 means not belonging to S_L_gamma_minus_two_theta_eta.
**************************************************/
int check_z_norm(polyvecl *z) 
{
	int i, j;
	for (i = 0; i < L; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if ((z->vec[i].coeffs[j] > GAMMA_MINUS_TWO_ETA_THETA) || (z->vec[i].coeffs[j] < -GAMMA_MINUS_TWO_ETA_THETA))
			{
				return 0;
			}
		}
	}
	return 1;
}

/*************************************************
* Name:        check_c
*
* Description:    a function to check whether c has 256 coefficients
*              , where 60 of them are 1/-1 and the rest are 0.
*
* Arguments:   - poly *c: pointer to input c
*
* Returns 0/1. 1 means belonging to B��, 0 means not belonging to B��.
**************************************************/
int check_c(poly *c)
{
	int count = 0, i;
	for (i = 0; i < N; ++i)
	{
		if ((c->coeffs[i] == 1) || (c->coeffs[i] == (Q-1)))
		{
			count++;
		}
		else if (c->coeffs[i] != 0)
		{
			return 0;
		}
	}
	if (count == 60) { return 1; }
	else { return 0; }
}


/*************************************************
* Name:        equal_c
*
* Description:    a function to compare inputted c1 and c2
*
* Arguments:   - poly *c1: pointer to input c1
*             - poly *c2: pointer to input c2
*
* Returns 0/1. 1 means c1 = c2, 0 means c1 �� c2.
**************************************************/
int equal_c(poly *c1, poly* c2) 
{
	int i;
	for (i = 0; i < N; ++i)
	{
		if ((c1->coeffs[i]) != (c2->coeffs[i]))
		{
			return 0;
		}
	}
	return 1;
}


/*************************************************
* Name:        equal_I
*
* Description:    a function to compare inputted I1 and I2
*
* Arguments:   - polyvecm *I1: pointer to input I1
*             - polyvecm *I2: pointer to input I2
*
* Returns 0/1. 1 means I1 = I2, 0 means I1 �� I2.
**************************************************/
int equal_I(polyvecm *I1, polyvecm* I2) 
{
	int i, j;
	for (i = 0; i < M; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if ((I1->vec[i].coeffs[j]) != (I2->vec[i].coeffs[j]))
			{
				return 0;
			}
		}
	}
	return 1;
}
