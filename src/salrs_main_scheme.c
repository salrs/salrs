#include <stdint.h>
#include "randombytes.h"
#include "params_salrs.h"
#include "fips202.h"
#include "kyber_all.h"
#include "polyvec_salrs.h"
#include "generating.h"
#include "poly_calculations_salrs.h"
#include "packing_salrs.h"
#include "params_kyber.h"
#include "check_salrs.h"
#include "salrs_main_scheme.h"

/*************************************************
* Name:        setup
*
* Description:   setup for the whole system
* Arguments:
*
**************************************************/
void setup_scheme()
{
        //we have preset all parameters in params_salrs.h 
}


/*************************************************
* Name:        master_key_gen
*
* Description:   MasterKeyGen() in the scheme
*             generate mpk and msk
* Arguments:   unsigned char *mpk: pointer to output mpk in the scheme
*             unsigned char *msk: pointer to output msk in the scheme
*
**************************************************/
void master_key_gen_scheme(unsigned char *mpk, unsigned char *msk)
{
	unsigned int i, j;
	polyvecl A[K];
	polyveck t;
	polyvecl s;
	poly tmp;


	unsigned char pk[SIZE_PKKEM], sk[SIZE_SKKEM];
	crypto_kem_keypair_kyber(pk, sk);

	generate_L_eta(&s);

	expand_matA(A);
	for (i = 0; i < K; ++i) {
		poly_multiplication(&A[i].vec[0], &s.vec[0], &t.vec[i]);
		for (j = 1; j < L; ++j)
		{
			poly_multiplication(&A[i].vec[j], &s.vec[j], &tmp);
			poly_addition(&t.vec[i], &tmp, &t.vec[i]);
		}
	}
	pack_mpk(pk, &t, mpk);
	pack_msk(sk, &s, msk);
}

/*************************************************
* Name:        derived_public_key_gen
*
* Description:   DerivedPublicKeyGen() in the scheme
*             generate dpk
* Arguments:   unsigned char*mpk: pointer to input mpk in the scheme
*             unsigned char*dpk: pointer to output dpk in the scheme
*
**************************************************/
void derived_public_key_gen_scheme(unsigned char* mpk, unsigned char* dpk)
{
	unsigned int i, j;
	unsigned char pk[SIZE_PKKEM];
	polyveck t;
	polyveck t2;
	polyveck t_up;
	polyvecl A[K];
	unpack_mpk(mpk, pk, &t);
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	unsigned char ss[32];
	polyvecl s2;

	crypto_kem_enc_kyber(ct, ss, pk);
	expand_V(ss, &s2);
	expand_matA(A);
	poly tmp;

/**         for (i = 0; i < N; ++i)
        {
              tmp.coeffs[i] = 0;
              t2.vec[0].coeffs[i] = 0;
        }
**/	
        for (i = 0; i < K; ++i) 
        {
		poly_multiplication(&A[i].vec[0], &s2.vec[0], &t2.vec[i]);
	 	for (j = 1; j < L; ++j)
		{
			poly_multiplication(&A[i].vec[j], &s2.vec[j], &tmp);
			poly_addition(&t2.vec[i], &tmp, &t2.vec[i]);
		}
	}
	for (i = 0; i < K; ++i)
	{
		poly_addition(&t.vec[i], &t2.vec[i], &t_up.vec[i]);
	}
	pack_dpk(ct, &t_up, dpk);     

}
/*************************************************
* Name:        derived_public_key_owner_check
*
* Description:   DerivedPublicKeyOwnerCheck() in the scheme
*             check dpk by owner
* Arguments:   unsigned char*dpk: pointer to input dpk in the scheme
*             unsigned char*msk: pointer to input msk in the scheme
*             unsigned char*mpk: pointer to input mpk in the scheme
*
* Returns 1/0. 1 means it is a valid dpk, 0 means it is not a valid dpk
**************************************************/
int derived_public_key_owner_check_scheme(unsigned char *dpk, unsigned char *msk, unsigned char *mpk)
{
	unsigned int i, j;
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	unsigned char sk[SIZE_SKKEM];
	unsigned char ss[32];
	unsigned char pk[SIZE_SKKEM];
	polyveck t_up;
	polyveck t;
	polyveck t2;
	polyvecl s;
	polyvecl s2;
	polyvecl A[K];
	unpack_dpk(dpk, ct, &t_up);
	unpack_msk(msk, sk, &s);
	unpack_mpk(mpk, pk, &t);

	for (i = 0; i < K; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if (t_up.vec[i].coeffs[j] > Q_2 || t_up.vec[i].coeffs[j] < -Q_2)
			{ 
                                printf("it's wrong\n");
				return 0;
			}
		}
	}
        
	crypto_kem_dec_kyber(ss, ct, sk);
	expand_V(ss, &s2);
	expand_matA(A);
	poly tmp;
         for (i = 0; i < N; ++i)
        {
              tmp.coeffs[i] = 0;
              t2.vec[0].coeffs[i] = 0;
        }
	for (i = 0; i < K; ++i) 
        {
	    poly_multiplication(&A[i].vec[0], &s2.vec[0], &t2.vec[i]); 
		for (j = 1; j < L; ++j)
		{
			poly_multiplication(&A[i].vec[j], &s2.vec[j], &tmp);
			poly_addition(&t2.vec[i], &tmp, &t2.vec[i]);
		}
	}

	for (i = 0; i < K; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if (t_up.vec[i].coeffs[j] != reduce(t.vec[i].coeffs[j] + t2.vec[i].coeffs[j]))
			{
				return 0;
			}
		}
	}
	return 1;
}

/*************************************************
* Name:        derived_public_key_public_check
*
* Description:   DerivedPublicKeyPublicCheck() in the scheme
*             check dpk
* Arguments:   unsigned char*dpk: pointer to input dpk in the scheme
*
* Returns 1/0. 1 means it is a valid dpk, 0 means it is an invalid dpk
**************************************************/
int derived_public_key_public_check_scheme(unsigned char *dpk)
{
	unsigned int i, j;
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	polyveck t;

	unpack_dpk(dpk, ct, &t);
	for (i = 0; i < K; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if (t.vec[i].coeffs[j] > Q_2 || t.vec[i].coeffs[j] < -Q_2)
			{
				return 0;
			}
		}
	}
	return 1;
}

/*************************************************
* Name:        sign_salrs
*
* Description:   sign() in the scheme
*
* Arguments:   - unsigned char * m: point to input message
*             - unsigned int len: the length of message
*             - unsigned char **Ring: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r:r in Ring = (dpk1, dpk2.....dpkr)
*             - unsigned char * dpk: point to input dpk
*             - unsigned char * mpk: point to input mpk
*             - unsigned char * msk: point to input msk
*             - unsigned char * sig: point to output signature
*
* Returns n/-1. n means it is a valid signature where n is positive and means the round of 
* rejection(n = a means a - 1 rejections), -1 means it is an invalid signature
**************************************************/
int sign_salrs_scheme(unsigned char *m, unsigned int len,unsigned char (*Ring)[SIZE_DPK],
	unsigned int r, unsigned char *dpk, unsigned char* mpk, unsigned char *msk, unsigned char *sig)
{       
	unsigned int i, j;
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	unsigned char sk[SIZE_SKKEM];
	unsigned char ss[32];
	polyvecl A[K];
	polyvecl H[M];
	poly c, c1;
	polyvecl s;
	polyvecl si;
	polyvecl s_up;
        polyvecl z;
	polyveck t_up;
	polyvecl y;
	polyvecm I;
	polyveck w;
	polyvecm v;
	int flag = 0, flag2 = -1, flag_dpk = 0, count = 0;
	unsigned int ii = 0;
        unsigned char tmp_dpk[SIZE_DPK];
        for (i = 0; i < SIZE_DPK; ++i)
        {
                tmp_dpk[i] = Ring[0][i];
        }
        for (i = 1; i < r; ++i)
        {
                for (j = 0; j < SIZE_DPK; ++j)
                {
                         if(tmp_dpk[j] != Ring[i][j])
                         {
                                  flag_dpk = 1;
                                  break;
                         }
                }
                if(flag_dpk == 0)
                {
                         printf("\nit's not a valid ring, there are repeated elements in the ring\n");
                         return -1;
                }
                flag_dpk = 0;
        }
        //unsigned char z_char[RSIZE_MAX + 5][PACK_Z_SIZE + 5];

	for (i = 0; i < r; ++i)
	{
		flag = 1;
		for (j = 0; j < SIZE_DPK; ++j)
		{
			if (dpk[j] != Ring[i][j])
			{
				flag = 0;
			}
		}
		if (flag == 1)
		{
			ii = i;
                        flag2 = 0;
			unpack_dpk(dpk, ct, &t_up);
		}
	}
        if (flag2 == -1)
        {
                printf("\nyou have no access to do the sign\n");
                return -1;
        } 

	Hm(&t_up, H);


	unpack_msk(msk, sk, &s);
	crypto_kem_dec_kyber(ss, ct, sk);

	expand_V(ss, &si);

        flag2 = derived_public_key_owner_check_scheme(dpk, msk, mpk);
        if (flag2 == 0)
        {
                printf("\nyou have no access to do the sign\n");
                return -1;
        } 

	for (i = 0; i < L; ++i)
	{
		poly_addition(&s.vec[i], &si.vec[i], &s_up.vec[i]);
	}
	expand_matA(A);
        polyveck as;
        poly tmp2;
        for (i = 0; i < K; ++i)
        {
                poly_multiplication(&A[i].vec[0], &s_up.vec[0], &as.vec[i]);
                for (j = 1; j < L; ++j)
                {
                         poly_multiplication(&A[i].vec[j], &s_up.vec[j], &tmp2);
                         poly_addition(&as.vec[i], &tmp2, &as.vec[i]);
                }
        }//
	poly tmp;
	for (i = 0; i < M; ++i) {
		poly_multiplication(&H[i].vec[0], &s_up.vec[0], &I.vec[i]);
		for (j = 1; j < L; ++j)
		{
			poly_multiplication(&H[i].vec[j], &s_up.vec[j], &tmp);
			poly_addition(&I.vec[i], &tmp, &I.vec[i]);
		}
	}

//rej:
        int rejection = 1;
        while (rejection == 1)
        {
        rejection = 0;
	//step4
        count++;
	generate_L_gamma(&y);

	for (i = 0; i < K; ++i) {
		poly_multiplication(&A[i].vec[0], &y.vec[0], &w.vec[i]);
		for (j = 1; j < L; ++j)
		{
			poly_multiplication(&A[i].vec[j], &y.vec[j], &tmp);
			poly_addition(&w.vec[i], &tmp, &w.vec[i]);
		}
	}

	for (i = 0; i < M; ++i) {
		poly_multiplication(&H[i].vec[0], &y.vec[0], &v.vec[i]);
		for (j = 1; j < L; ++j)
		{
			poly_multiplication(&H[i].vec[j], &y.vec[j], &tmp);
			poly_addition(&v.vec[i], &tmp, &v.vec[i]);
		}
	}
	polyveck az;
	polyveck cti;
	polyvecm hz;
	polyvecm cI;
	polyvecl cs;
	unsigned int i_main = ii + 1;
	for (i_main = ii + 1; i_main < ii + r; i_main++)
	{
		unpack_dpk(Ring[i_main % r], ct, &t_up);

		Hm(&t_up, H);
		H_theta(m, len, Ring, r, &w, &v, &I, &c);
                if (i_main % r == 0)
                {
                        for (i = 0; i < N; ++i)
                        {
                                c1.coeffs[i] = c.coeffs[i];
                        }
                }
		generate_L_gamma_sub_to_theta_eta(&z);
                pack_polyvecl_gmte(&z, sig + (i_main % r) * PACK_Z_SIZE);

		for (i = 0; i < K; ++i) {
			poly_multiplication(&A[i].vec[0], &z.vec[0], &az.vec[i]);
			for (j = 1; j < L; ++j)
			{
				poly_multiplication(&A[i].vec[j], &z.vec[j], &tmp);
				poly_addition(&az.vec[i], &tmp, &az.vec[i]);
			}
		}

		for (j = 0; j < K; ++j)
		{
			poly_multiplication(&t_up.vec[j], &c, &cti.vec[j]);
                        for (i = 0; i < N; ++i)
                        {
                                cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i]);
                        }
		}
		for (i = 0; i < K; ++i)
		{
			//poly_substraction(&az.vec[i], &cti.vec[i], &w.vec[i]);
                        poly_addition(&az.vec[i], &cti.vec[i], &w.vec[i]);
		}

		for (i = 0; i < M; ++i) {
			poly_multiplication(&H[i].vec[0], &z.vec[0], &hz.vec[i]);
			for (j = 1; j < L; ++j)
			{
				poly_multiplication(&H[i].vec[j], &z.vec[j], &tmp);
				poly_addition(&hz.vec[i], &tmp, &hz.vec[i]);
			}
		}

		for (j = 0; j < M; ++j)
		{
			poly_multiplication(&I.vec[j], &c, &cI.vec[j]);
                        for (i = 0; i < N; ++i)
                        {
                                cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i]);
                        }
		}
		for (i = 0; i < M; ++i)
		{
			//poly_substraction(&hz.vec[i], &cI.vec[i], &v.vec[i]);
                        poly_addition(&hz.vec[i], &cI.vec[i], &v.vec[i]);
		}
	}
	H_theta(m, len, Ring, r, &w, &v, &I, &c);

        if (ii == 0)
        {
                for (i = 0; i < N; ++i)
                {
                        c1.coeffs[i] = c.coeffs[i];
                }
        }

	for (j = 0; j < L; ++j)
	{
		poly_multiplication(&s_up.vec[j], &c, &cs.vec[j]);
	}
	for (i = 0; i < L; ++i)
	{
		poly_addition(&y.vec[i], &cs.vec[i], &z.vec[i]);
	}
        pack_polyvecl_gmte(&z, sig + ii * PACK_Z_SIZE);
        unpack_dpk(dpk, ct, &t_up);
	Hm(&t_up, H);
	for (i = 0; i < L; ++i)
	{
		for (j = 0; j < N; ++j)
		{
			if ((z.vec[i].coeffs[j] >(GAMMA_MINUS_TWO_ETA_THETA)) || (z.vec[i].coeffs[j] < -(GAMMA_MINUS_TWO_ETA_THETA)))
			{
				//goto rej;
                                rejection = 1;
			}
		}
	}
        }
	pack_sig(&c1, r, &I, sig);
        return count;
}

/*************************************************
* Name:        verify_salrs
*
* Description:   verify() in the scheme
*
* Arguments:   - unsigned char * m: point to input message
*             - unsigned int len: the length of message
*             - unsigned char (*Ring)[SIZE_DPK]: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r:r in R = (dpk1, dpk2.....dpkr)
*             - unsigned char * sig: point to input signature
*
* Returns 1/0. 1 means it is a valid signature , 0 means it is an invalid signature
**************************************************/
int verify_salrs_scheme(unsigned char*m, unsigned int len,
unsigned char (*Ring)[SIZE_DPK], unsigned int r, unsigned char* sig)
{
	unsigned int i, j, i_main;
        int flag = 0, flag_dpk = 0;
	poly c, c1, tmp;
	polyvecm I;
	//unsigned int count = 0;
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	polyvecl A[K];
	polyvecl H[M];
	polyveck t_up;
	polyveck w;
	polyvecm v;
	polyveck az;
	polyveck cti;
	polyvecm hz;
	polyvecm cI;
        polyvecl z;
        unsigned char tmp_dpk[SIZE_DPK];
        for (i = 0; i < SIZE_DPK; ++i)
        {
                tmp_dpk[i] = Ring[0][i];
        }
        for (i = 1; i < r; ++i)
        {
                for (j = 0; j < SIZE_DPK; ++j)
                {
                         if(tmp_dpk[j] != Ring[i][j])
                         {
                                  flag_dpk = 1;
                                  break;
                         }
                }
                if(flag_dpk == 0)
                {
                         printf("\nit's not a valid ring, there are repeated elements in the ring\n");
                         return 0;
                }
                flag_dpk = 0;
        }
        //unsigned char z_char[RSIZE_MAX + 5][PACK_Z_SIZE + 5];


	flag = unpack_sig(sig, &c1, r, &I);
        if (flag == -1)
        {
              printf("unpack sig failed in verify\n");
              return 0;
        }

	for (i = 0; i < N; ++i)
	{
		c.coeffs[i] = c1.coeffs[i];
	}
	flag = check_c(&c);
	if (flag == 0)
	{
                printf("check_c failed in verify\n");
		return 0;
	}

	expand_matA(A);

	for (i_main = 0; i_main < r; i_main++)
	{
		unpack_dpk(Ring[i_main], ct, &t_up);
		Hm(&t_up, H);
                unpack_polyvecl_gmte(sig + i_main * PACK_Z_SIZE, &z);
                flag = check_z_norm(&z);
                if (flag == 0) { return 0; }

		for (i = 0; i < K; ++i) {
			poly_multiplication(&A[i].vec[0], &z.vec[0], &az.vec[i]);
			for (j = 1; j < L; ++j)
			{
				poly_multiplication(&A[i].vec[j], &z.vec[j], &tmp);
				poly_addition(&az.vec[i], &tmp, &az.vec[i]);
			}
		}
		for (j = 0; j < K; ++j)
		{
			poly_multiplication(&t_up.vec[j], &c, &cti.vec[j]);
                        for (i = 0; i < N; ++i)
                        {
                                cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i]);
                        }
		}
		for (i = 0; i < K; ++i)
		{
			//poly_substraction(&az.vec[i], &cti.vec[i], &w.vec[i]);
                        poly_addition(&az.vec[i], &cti.vec[i], &w.vec[i]);
		}
                for (i = 0; i < M; ++i)
                {
			poly_multiplication(&H[i].vec[0], &z.vec[0], &hz.vec[i]);
			for (j = 1; j < L; ++j)
			{
				poly_multiplication(&H[i].vec[j], &z.vec[j], &tmp);
				poly_addition(&hz.vec[i], &tmp, &hz.vec[i]);
			}
		}
		for (j = 0; j < M; ++j)
		{
			poly_multiplication(&I.vec[j], &c, &cI.vec[j]);
                        for (i = 0; i < N; ++i)
                        {
                                cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i]);
                        }
		}
		for (i = 0; i < M; ++i)
		{
			//poly_substraction(&hz.vec[i], &cI.vec[i], &v.vec[i]);
                        poly_addition(&hz.vec[i], &cI.vec[i], &v.vec[i]);
		}
		H_theta(m, len, Ring, r, &w, &v, &I, &c); 
	}
	for (i = 0; i < N; ++i)
	{
		if (c.coeffs[i] != c1.coeffs[i])
		{
                        printf("something is wrong when comparing c1 and cr+1\n");
			return 0;
		}
	}

	return 1;
}

/*************************************************
* Name:        link
*
* Description:   link() in the scheme
*
* Arguments:   - unsigned char * sig1: point to input signature_1
*             - unsigned char * m1: point to input message
*             - unsigned int len1: the length of message
*             - unsigned char (*Ring1)[SIZE_DPK]: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r1:r1 in Ring1 = (dpk1, dpk2.....dpkr)
*             - unsigned char * sig2: point to input signature_2
*             - unsigned char * m2: point to input message
*             - unsigned int len2: the length of message
*             - unsigned char (*Ring2)[SIZE_DPK]: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r2:r2 in Ring2 = (dpk1, dpk2.....dpkr)
*
* Returns 1/0. 1 means it is a valid link, 0 means it is an invalid link
**************************************************/
int link_salrs_scheme(unsigned char *sig1, unsigned char*m1, unsigned int len1,
unsigned char (*Ring1)[SIZE_DPK],unsigned int r1,
unsigned char *sig2, unsigned char*m2, unsigned int len2,
unsigned char (*Ring2)[SIZE_DPK],unsigned int r2)
{
        int flag1 = 1, flag2 = 1, flag_dpk = 0;
        unsigned int i, j;
	poly c1, c2;
	polyvecm I1, I2;
        unsigned char tmp_dpk[SIZE_DPK];
        for (i = 0; i < SIZE_DPK; ++i)
        {
                tmp_dpk[i] = Ring1[0][i];
        }
        for (i = 1; i < r1; ++i)
        {
                for (j = 0; j < SIZE_DPK; ++j)
                {
                         if(tmp_dpk[j] != Ring1[i][j])
                         {
                                  flag_dpk = 1;
                                  break;
                         }
                }
                if(flag_dpk == 0)
                {
                         printf("\nRing1 is not a valid ring, there are repeated elements in Ring1\n");
                         return 0;
                }
                flag_dpk = 0;
        }
        for (i = 0; i < SIZE_DPK; ++i)
        {
                tmp_dpk[i] = Ring2[0][i];
        }
        for (i = 1; i < r2; ++i)
        {
                for (j = 0; j < SIZE_DPK; ++j)
                {
                         if(tmp_dpk[j] != Ring2[i][j])
                         {
                                  flag_dpk = 1;
                                  break;
                         }
                }
                if(flag_dpk == 0)
                {
                         printf("\nRing2 is not a valid ring, there are repeated elements in Ring2\n");
                         return 0;
                }
                flag_dpk = 0;
        }
        //unsigned char z1[RSIZE_MAX + 5][PACK_Z_SIZE + 5], z2[RSIZE_MAX + 5][PACK_Z_SIZE + 5];

        flag1 = verify_salrs_scheme(m1, len1, Ring1, r1, sig1);
        flag2 = verify_salrs_scheme(m2, len2, Ring2, r2, sig2);
        if (flag1 == 0 || flag2 == 0)
        {
              printf("verify signature failed in link\n");
	      return 0;
        }
	unpack_sig(sig1, &c1, r1, &I1);
	unpack_sig(sig2, &c2, r2, &I2);

	return equal_I(&I1, &I2);
}
