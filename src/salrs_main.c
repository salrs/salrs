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
#include "salrs_main.h"
#include "api_kyber.h"
#include "inttypes.h"

#define gen_a(A,B)  gen_matrix_kyber(A,B,0)
#define gen_at(A,B) gen_matrix_kyber(A,B,1)

/*************************************************
* Name:        Setup
*
* Description:   setup for the whole system
* Arguments:
*
**************************************************/
void Setup()
{
        //we have preset all parameters in params_salrs.h 
}

/*************************************************
* Name:        MasterSeedGen
*
* Description:   a probabilistic algorithm to generate a seed which is used for MasterKeyGen()
* Arguments:   unsigned char *seed: the output seed
*
**************************************************/
void MasterSeedGen(unsigned char *seed)
{
/**
	polyvecl s;
       int i = 0;
       unsigned char pk[SIZE_PKKEM], sk[SIZE_SKKEM];
	crypto_kem_keypair_kyber(pk, sk);

	generate_L_eta(&s);
	for (i = 0; i < SIZE_PKKEM; ++i)//pk_kem string
		seed[i] = pk[i];
	seed += SIZE_PKKEM;
        for (i = 0; i < SIZE_SKKEM; ++i)//sk_kem string
		seed[i] = sk[i];
	seed += SIZE_SKKEM;

	pack_polyvecl_eta(&s, seed);
**/

	randombytes_kyber(seed, KYBER_SYMBYTES);
	sha3_512_kyber(seed, seed, KYBER_SYMBYTES);

        seed += KYBER_SYMBYTES + KYBER_SYMBYTES;

	polyvecl s;
	generate_L_eta(&s);
	pack_polyvecl_eta(&s, seed);
}



/*************************************************
* Name:        MasterKeyGen
*
* Description:  a deterministic algorithm to generate MPK, MSVK and MSSK using a seed generated by *               MasterSeedGen()
* Arguments:  unsigned char *seed: pointer to input seed
*             unsigned char *MPK: pointer to output MPK
*             unsigned char *MSVK: pointer to output MSVK
*             unsigned char *MSSK: pointer to output MSSK
*
**************************************************/
void MasterKeyGen(unsigned char *seed, unsigned char *MPK, unsigned char *MSVK, unsigned char *MSSK)
{
        unsigned int i, j;
	polyvecl A[K];
	polyveck t;
	polyvecl s;
	poly tmp;

	polyvec_kyber a[KYBER_K], e, pkpv, skpv;
	unsigned char pk[SIZE_PKKEM];
	unsigned char *publicseed = seed;
	unsigned char *noiseseed = seed + KYBER_SYMBYTES;
	unsigned char nonce = 0;

	gen_a(a, publicseed);

	for (i = 0; i<KYBER_K; i++)
		poly_getnoise_kyber(skpv.vec + i, noiseseed, nonce++);

	polyvec_ntt_kyber(&skpv);

	for (i = 0; i<KYBER_K; i++)
		poly_getnoise_kyber(e.vec + i, noiseseed, nonce++);

	// matrix-vector multiplication
	for (i = 0; i<KYBER_K; i++)
		polyvec_pointwise_acc_kyber(&pkpv.vec[i], &skpv, a + i);

	polyvec_invntt_kyber(&pkpv);
	polyvec_add_kyber(&pkpv, &pkpv, &e);

	pack_sk_kyber(MSVK, &skpv);
	pack_pk_kyber(pk, &pkpv, publicseed);
	for (i = 0; i<KYBER_INDCPA_PUBLICKEYBYTES; i++)
		MSVK[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
	sha3_256_kyber(MSVK + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
	randombytes_kyber(MSVK + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
   
        seed += KYBER_SYMBYTES + KYBER_SYMBYTES;
        unpack_polyvecl_eta(seed, &s);

/**
	unsigned char pk[SIZE_PKKEM];
        for (i = 0; i < SIZE_PKKEM; ++i)//pk_kem string
		pk[i] = seed[i];
	seed += SIZE_PKKEM;
        for (i = 0; i < SIZE_SKKEM; ++i)//sk_kem string
		MSVK[i] = seed[i];
	seed += SIZE_SKKEM;
        unpack_polyvecl_eta(seed, &s);
**/

	expand_matA(A);
	for (i = 0; i < K; ++i) {
		poly_multiplication(&A[i].vec[0], &s.vec[0], &t.vec[i]);
		for (j = 1; j < L; ++j)
		{
			poly_multiplication(&A[i].vec[j], &s.vec[j], &tmp);
			poly_addition(&t.vec[i], &tmp, &t.vec[i]);
		}
	}
	pack_mpk(pk, &t, MPK);
        pack_polyvecl_eta(&s, MSSK);
}

/*************************************************
* Name:        MasterPublicKeyPublicCheck
*
* Description:  a function used to publicly check MPK
* Arguments:  unsigned char *seed: pointer to input MPK
*
* Returns 1/0. 1 means it is a valid Mpk, 0 means it is not a valid MPK
**************************************************/
int MasterPublicKeyPublicCheck(unsigned char *MPK)
{
        unsigned int i, j;
        unsigned char pk[SIZE_PKKEM];
	polyveck t;
        unpack_mpk(MPK, pk, &t);
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
* Name:        DerivedPublicKeyGen
*
* Description:   DerivedPublicKeyGen()
*             generate DPK
* Arguments:   unsigned char *MPK: pointer to input MPK
*             unsigned char *DPK: pointer to output DPK
*
**************************************************/
void DerivedPublicKeyGen(unsigned char* MPK, unsigned char* DPK)
{
        unsigned int i, j;
	unsigned char pk[SIZE_PKKEM];
	polyveck t;
	polyveck t2;
	polyveck t_up;
	polyvecl A[K];
	unpack_mpk(MPK, pk, &t);
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
	pack_dpk(ct, &t_up, DPK);     
}


/*************************************************
* Name:        DerivedPublicKeyOwnerCheck
*
* Description:   DerivedPublicKeyOwnerCheck()
*             check DPK by owner
* Arguments:   unsigned char *DPK: pointer to input DPK
*             unsigned char *MPK: pointer to input MPK
*             unsigned char *MSVK: pointer to input MSVK
*
* Returns 1/0. 1 means it is a valid dpk, 0 means it is not a valid dpk
**************************************************/
int DerivedPublicKeyOwnerCheck(unsigned char *DPK, unsigned char *MPK, unsigned char *MSVK)
{
        unsigned int i, j;
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	unsigned char ss[32];
	unsigned char pk[SIZE_SKKEM];
	polyveck t_up;
	polyveck t;
	polyveck t2;
	polyvecl s2;
	polyvecl A[K];
	unpack_dpk(DPK, ct, &t_up);
	unpack_mpk(MPK, pk, &t);

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
        
	crypto_kem_dec_kyber(ss, ct, MSVK);

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
* Name:        DerivedPublicKeyPublicCheck
*
* Description:   DerivedPublicKeyPublicCheck()
*             check dpk
* Arguments:   unsigned char *DPK: pointer to input DPK in the scheme
*
* Returns 1/0. 1 means it is a valid DPK, 0 means it is an invalid DPK
**************************************************/
int DerivedPublicKeyPublicCheck(unsigned char* DPK)
{
        unsigned int i, j;
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	polyveck t;

	unpack_dpk(DPK, ct, &t);
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
* Name:        Sign
*
* Description:   Sign()
*
* Arguments:   - unsigned char * m: point to input message
*             - unsigned int mlen: the length of message
*             - unsigned char **Ring: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r:r in Ring = (dpk1, dpk2.....dpkr)
*             - unsigned char *DPK: point to input DPK
*             - unsigned char *MPK: point to input MPK
*             - unsigned char *MSVK: point to input MSVK
*             - unsigned char *MSSK: point to input MSSK
*             - unsigned char *sig: point to output signature
*             - unsigned char *key_image: point to output key_image
*
* Returns n/-1. n means it is a valid signature where n is positive and means the round of 
* rejection(n = a means a - 1 rejections), -1 means it is an invalid signature
**************************************************/
int Sign(unsigned char *m, unsigned int mlen, unsigned char (*Ring)[SIZE_DPK],unsigned int r, unsigned char *DPK, unsigned char* MPK, unsigned char *MSVK, unsigned char *MSSK, unsigned char *sig, unsigned char *key_image)
{
        unsigned int i, j;
	unsigned char ct[KYBER_CIPHERTEXTBYTES];
	unsigned char ss[32];
	polyvecl A[K];
	polyvecl H[M];
        polyvecl s;
	poly c, c1;
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
			if (DPK[j] != Ring[i][j])
			{
				flag = 0;
			}
		}
		if (flag == 1)
		{
			ii = i;
                        flag2 = 0;
			unpack_dpk(DPK, ct, &t_up);
		}
	}
        if (flag2 == -1)
        {
                printf("\nyou have no access to do the sign\n");
                return -1;
        } 

	Hm(&t_up, H);

        unpack_polyvecl_eta(MSSK, &s);
	crypto_kem_dec_kyber(ss, ct, MSVK);

	expand_V(ss, &si);

        flag2 = DerivedPublicKeyOwnerCheck(DPK, MPK, MSVK);
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
		H_theta(m, mlen, Ring, r, &w, &v, &I, &c);
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
	H_theta(m, mlen, Ring, r, &w, &v, &I, &c);

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
        unpack_dpk(DPK, ct, &t_up);
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
        pack_polyvecm_q(&I, key_image);
        return count;
}

/*************************************************
* Name:        Verify
*
* Description:   Verify()
*
* Arguments:   - unsigned char * m: point to input message
*             - unsigned int mlen: the length of message
*             - unsigned char (*Ring)[SIZE_DPK]: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r:r in R = (dpk1, dpk2.....dpkr)
*             - unsigned char * sig: point to input signature
*             - unsigned char *key_image: point to output key_image
*
* Returns 1/0. 1 means it is a valid signature , 0 means it is an invalid signature
**************************************************/
int Verify(unsigned char *m, unsigned int mlen,unsigned char (*Ring)[SIZE_DPK], unsigned int r, unsigned char* sig, unsigned char *key_image)
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
        pack_polyvecm_q(&I, key_image);
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
		H_theta(m, mlen, Ring, r, &w, &v, &I, &c); 
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
* Name:        Link
*
* Description:   link()
*
* Arguments:   - unsigned char * sig1: point to input signature_1
*             - unsigned char * m1: point to input message
*             - unsigned int mlen1: the length of message
*             - unsigned char (*Ring1)[SIZE_DPK]: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r1:r1 in Ring1 = (dpk1, dpk2.....dpkr)
*             - unsigned char * sig2: point to input signature_2
*             - unsigned char * m2: point to input message
*             - unsigned int mlen2: the length of message
*             - unsigned char (*Ring2)[SIZE_DPK]: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r2:r2 in Ring2 = (dpk1, dpk2.....dpkr)
*
* Returns 1/0. 1 means it is a valid link, 0 means it is an invalid link
**************************************************/
int Link(unsigned char *sig1, unsigned char *m1, unsigned int mlen1,
unsigned char (*Ring1)[SIZE_DPK],unsigned int r1,
	unsigned char *sig2, unsigned char *m2, unsigned int mlen2,
unsigned char (*Ring2)[SIZE_DPK],unsigned int r2)
{ 
        int flag1 = 1, flag2 = 1, flag_dpk = 0;
        unsigned int i, j;
	poly c1, c2;
	polyvecm I1, I2;
        unsigned char tmp_dpk[SIZE_DPK], key_image[PACK_I_SIZE];
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

        flag1 = Verify(m1, mlen1, Ring1, r1, sig1, key_image);
        flag2 = Verify(m2, mlen2, Ring2, r2, sig2, key_image);
        if (flag1 == 0 || flag2 == 0)
        {
              printf("verify signature failed in link\n");
	      return 0;
        }
	unpack_sig(sig1, &c1, r1, &I1);
	unpack_sig(sig2, &c2, r2, &I2);

	return equal_I(&I1, &I2);
}


