#include "params_salrs.h"
#include "polyvec_salrs.h"
#include "packing_salrs.h"

//pack and unpack functions

/*************************************************
* Name:        pack_polyveck_q
*
* Description: Bit-pack t = As.
*
* Arguments:    - polyveck *t: pointer to input vector t
*              - unsigned char *t_char: pointer to output array
**************************************************/
void pack_polyveck_q(polyveck *t,
	unsigned char *t_char) 
{
	int i, j;
	long long tmp[2];
	for (i = 0; i < K; ++i)
	{
		for (j = 0; j < 128; ++j)
		{
                       // printf("%lld %lld ", t->vec[i].coeffs[2 * j], t->vec[i].coeffs[2 * j + 1]);
			tmp[0] = t->vec[i].coeffs[2 * j] + Q_2;
			tmp[1] = t->vec[i].coeffs[2 * j + 1] + Q_2;
			t_char[i * 128 * 9 + 9 * j + 0] = (char)tmp[0];
			t_char[i * 128 * 9 + 9 * j + 1] = (char)(tmp[0] >> 8);
			t_char[i * 128 * 9 + 9 * j + 2] = (char)(tmp[0] >> 16);
			t_char[i * 128 * 9 + 9 * j + 3] = (char)(tmp[0] >> 24);
			t_char[i * 128 * 9 + 9 * j + 4] = (char)(tmp[0] >> 32) | (char)(tmp[1] << 4);
			t_char[i * 128 * 9 + 9 * j + 5] = (char)(tmp[1] >> 4);
			t_char[i * 128 * 9 + 9 * j + 6] = (char)(tmp[1] >> 12);
			t_char[i * 128 * 9 + 9 * j + 7] = (char)(tmp[1] >> 20);
			t_char[i * 128 * 9 + 9 * j + 8] = (char)(tmp[1] >> 28);
		}
	}
 
}


/*************************************************
* Name:        unpack_polyveck_q
*
* Description:  unpack t = As.
*
* Arguments:   - unsigned char *t_char: pointer to input array
*              - polyveck *t: pointer to output vector t
**************************************************/
void unpack_polyveck_q(unsigned char *t_char,
	polyveck *t)
{
	int i, j;
	long long tmp[2];
	for (i = 0; i < K; ++i)
	{
		for (j = 0; j < 128; ++j)
		{
			tmp[0]  = (long long)t_char[i * 128 * 9 + 9 * j + 0];
			tmp[0] |= ((long long)t_char[i * 128 * 9 + 9 * j + 1]) << 8;
			tmp[0] |= ((long long)t_char[i * 128 * 9 + 9 * j + 2]) << 16;
			tmp[0] |= ((long long)t_char[i * 128 * 9 + 9 * j + 3]) << 24;
			tmp[0] |= (((long long)t_char[i * 128 * 9 + 9 * j + 4]) << 32)&(0xFFFFFFFFF);
			tmp[1]  = ((long long)t_char[i * 128 * 9 + 9 * j + 4]) >> 4;
			tmp[1] |= ((long long)t_char[i * 128 * 9 + 9 * j + 5]) << 4;
			tmp[1] |= ((long long)t_char[i * 128 * 9 + 9 * j + 6]) << 12;
			tmp[1] |= ((long long)t_char[i * 128 * 9 + 9 * j + 7]) << 20;
			tmp[1] |= (((long long)t_char[i * 128 * 9 + 9 * j + 8]) << 28)&(0xFFFFFFFFF);

			t->vec[i].coeffs[2 * j] = tmp[0] - Q_2;
			t->vec[i].coeffs[2 * j + 1] = tmp[1] - Q_2;
                      //  printf("%lld %lld ", t->vec[i].coeffs[2 * j], t->vec[i].coeffs[2 * j + 1]);
		}
	}
}


/*************************************************
* Name:        pack_polyvecl_eta
*
* Description: Bit-pack s <- Sl_eta.
*
* Arguments:    - polyvecl *s: pointer to input vector s
*              - unsigned char *s_char: pointer to output array
**************************************************/
void pack_polyvecl_eta(polyvecl *s,
	unsigned char *s_char) 
{
	int i, j;
	long long tmp[8];
	for (i = 0; i < L; ++i)
	{
		for (j = 0; j < 32; ++j)
		{
			tmp[0] = s->vec[i].coeffs[8 * j + 0] + ETA;
			tmp[1] = s->vec[i].coeffs[8 * j + 1] + ETA;
			tmp[2] = s->vec[i].coeffs[8 * j + 2] + ETA;
			tmp[3] = s->vec[i].coeffs[8 * j + 3] + ETA;
			tmp[4] = s->vec[i].coeffs[8 * j + 4] + ETA;
			tmp[5] = s->vec[i].coeffs[8 * j + 5] + ETA;
			tmp[6] = s->vec[i].coeffs[8 * j + 6] + ETA;
			tmp[7] = s->vec[i].coeffs[8 * j + 7] + ETA;

			s_char[i * 32 * 3 + j * 3 + 0] = ((char)tmp[0]) + ((char)tmp[1] << 3) + ((char)tmp[2] << 6);
			s_char[i * 32 * 3 + j * 3 + 1] = ((char)tmp[2] >> 2) + ((char)tmp[3] << 1) + ((char)tmp[4] << 4) + ((char)tmp[5] << 7);
			s_char[i * 32 * 3 + j * 3 + 2] = ((char)tmp[5] >> 1) + ((char)tmp[6] << 2) + ((char)tmp[7] << 5);
		}
	}
}


/*************************************************
* Name:        unpack_polyvecl_eta
*
* Description: unpack s <- Sl_eta.
*
* Arguments:   - unsigned char *s_char: pointer to input array
*              - polyvecl *s: pointer to output vector s
**************************************************/
void unpack_polyvecl_eta(unsigned char *s_char,
	polyvecl *s)
{
	int i, j;
	long long tmp[8];
	for (i = 0; i < L; ++i)
	{
		for (j = 0; j < 32; ++j)
		{
			tmp[0] = (long long)s_char[i * 32 * 3 + j * 3 + 0] & 0x7;
			tmp[1] = (long long)s_char[i * 32 * 3 + j * 3 + 0] >> 3 & 0x7;
			tmp[2] = ((long long)s_char[i * 32 * 3 + j * 3 + 0] >> 6 & 0x3) | ((long long)s_char[i * 32 * 3 + j * 3 + 1] << 2 & 0x4);
			tmp[3] = (long long)s_char[i * 32 * 3 + j * 3 + 1] >> 1 & 0x7;
			tmp[4] = (long long)s_char[i * 32 * 3 + j * 3 + 1] >> 4 & 0x7;
			tmp[5] = ((long long)s_char[i * 32 * 3 + j * 3 + 1] >> 7 & 0x1) | ((long long)s_char[i * 32 * 3 + j * 3 + 2] << 1 & 0x6);
			tmp[6] = (long long)s_char[i * 32 * 3 + j * 3 + 2] >> 2 & 0x7;
			tmp[7] = (long long)s_char[i * 32 * 3 + j * 3 + 2] >> 5 & 0x7;

			s->vec[i].coeffs[8 * j + 0] = tmp[0] - ETA;
			s->vec[i].coeffs[8 * j + 1] = tmp[1] - ETA;
			s->vec[i].coeffs[8 * j + 2] = tmp[2] - ETA;
			s->vec[i].coeffs[8 * j + 3] = tmp[3] - ETA;
			s->vec[i].coeffs[8 * j + 4] = tmp[4] - ETA;
			s->vec[i].coeffs[8 * j + 5] = tmp[5] - ETA;
			s->vec[i].coeffs[8 * j + 6] = tmp[6] - ETA;
			s->vec[i].coeffs[8 * j + 7] = tmp[7] - ETA;
		}
	}
}


/*************************************************
* Name:        pack_polyvecl_gmte
*
* Description:  Bit-pack z <- Sl_gamma_minus_two_theta_eta.
*
* Arguments:   - polyvecl *z: pointer to input vector z
*             - unsigned char *z_char: pointer to output array
**************************************************/
void pack_polyvecl_gmte(polyvecl *z,
	unsigned char *z_char) 
{
	int i, j;
	long long tmp[4];
	for (i = 0; i < L; ++i)
	{
		for (j = 0; j < 64; ++j)
		{
			tmp[0] = z->vec[i].coeffs[4 * j + 0] + GAMMA_MINUS_TWO_ETA_THETA;
			tmp[1] = z->vec[i].coeffs[4 * j + 1] + GAMMA_MINUS_TWO_ETA_THETA;
			tmp[2] = z->vec[i].coeffs[4 * j + 2] + GAMMA_MINUS_TWO_ETA_THETA;
			tmp[3] = z->vec[i].coeffs[4 * j + 3] + GAMMA_MINUS_TWO_ETA_THETA;
			z_char[i * 64 * 11 + 11 * j + 0] = (char)tmp[0];
			z_char[i * 64 * 11 + 11 * j + 1] = (char)(tmp[0] >> 8);
			z_char[i * 64 * 11 + 11 * j + 2] = ((char)(tmp[0] >> 16)) | ((char)(tmp[1] << 6));
			z_char[i * 64 * 11 + 11 * j + 3] = (char)(tmp[1] >> 2);
			z_char[i * 64 * 11 + 11 * j + 4] = (char)(tmp[1] >> 10);
			z_char[i * 64 * 11 + 11 * j + 5] = ((char)(tmp[1] >> 18)) | ((char)(tmp[2] << 4));
			z_char[i * 64 * 11 + 11 * j + 6] = (char)(tmp[2] >> 4);
			z_char[i * 64 * 11 + 11 * j + 7] = (char)(tmp[2] >> 12);
			z_char[i * 64 * 11 + 11 * j + 8] = ((char)(tmp[2] >> 20)) | ((char)(tmp[3] << 2));
			z_char[i * 64 * 11 + 11 * j + 9] = (char)(tmp[3] >> 6);
		    z_char[i * 64 * 11 + 11 * j + 10] = (char)(tmp[3] >> 14);
		}
	}
}



/*************************************************
* Name:        unpack_polyvecl_gmte
*
* Description:  Bit-pack z <- Sl_gamma_minus_two_theta_eta.
*
* Arguments:   - unsigned char *z_char: pointer to input array
*              - polyvecl *z: pointer to output vector z
**************************************************/
void unpack_polyvecl_gmte(unsigned char *z_char,
	polyvecl *z)
{
	int i, j;
	long long tmp[4];
	for (i = 0; i < L; ++i)
	{
		for (j = 0; j < 64; ++j)
		{
			tmp[0] = (long long)z_char[i * 64 * 11 + 11 * j + 0];
			tmp[0] |= ((long long)z_char[i * 64 * 11 + 11 * j + 1]) << 8;
			tmp[0] |= (((long long)z_char[i * 64 * 11 + 11 * j + 2]) << 16) & (0x3FFFFF);
			tmp[1] = ((long long)z_char[i * 64 * 11 + 11 * j + 2]) >> 6;
			tmp[1] |= ((long long)z_char[i * 64 * 11 + 11 * j + 3]) << 2;
			tmp[1] |= ((long long)z_char[i * 64 * 11 + 11 * j + 4]) << 10;
			tmp[1] |= (((long long)z_char[i * 64 * 11 + 11 * j + 5]) << 18) & (0x3FFFFF);
			tmp[2] = ((long long)z_char[i * 64 * 11 + 11 * j + 5]) >> 4;
			tmp[2] |= ((long long)z_char[i * 64 * 11 + 11 * j + 6]) << 4;
			tmp[2] |= ((long long)z_char[i * 64 * 11 + 11 * j + 7]) << 12;
			tmp[2] |= (((long long)z_char[i * 64 * 11 + 11 * j + 8]) << 20) & (0x3FFFFF);
			tmp[3] = ((long long)z_char[i * 64 * 11 + 11 * j + 8]) >> 2;
			tmp[3] |= ((long long)z_char[i * 64 * 11 + 11 * j + 9]) << 6;
			tmp[3] |= (((long long)z_char[i * 64 * 11 + 11 * j + 10]) << 14) & (0x3FFFFF);
			z->vec[i].coeffs[4 * j + 0] = tmp[0] - GAMMA_MINUS_TWO_ETA_THETA;
			z->vec[i].coeffs[4 * j + 1] = tmp[1] - GAMMA_MINUS_TWO_ETA_THETA;
			z->vec[i].coeffs[4 * j + 2] = tmp[2] - GAMMA_MINUS_TWO_ETA_THETA;
			z->vec[i].coeffs[4 * j + 3] = tmp[3] - GAMMA_MINUS_TWO_ETA_THETA;
		}
	}
}


/*************************************************
* Name:        pack_polyvecm_q
*
* Description:  Bit-pack m <- Rmq.
*
* Arguments:  - polyvecm *m: pointer to input vector m
*            - unsigned char *m_char: pointer to output array
**************************************************/
void pack_polyvecm_q(polyvecm *m,
	unsigned char *m_char) 
{
	int ii, j;
	long long tmp[2];
	for (ii = 0; ii < M; ++ii)
	{
		for (j = 0; j < 128; ++j)
		{
			tmp[0] = m->vec[ii].coeffs[2 * j] + Q_2;
			tmp[1] = m->vec[ii].coeffs[2 * j + 1] + Q_2;
			m_char[ii * 128 * 9 + 9 * j + 0] = (char)tmp[0];
			m_char[ii * 128 * 9 + 9 * j + 1] = (char)(tmp[0] >> 8);
			m_char[ii * 128 * 9 + 9 * j + 2] = (char)(tmp[0] >> 16);
			m_char[ii * 128 * 9 + 9 * j + 3] = (char)(tmp[0] >> 24);
			m_char[ii * 128 * 9 + 9 * j + 4] = ((char)(tmp[0] >> 32)) | ((char)(tmp[1] << 4));
			m_char[ii * 128 * 9 + 9 * j + 5] = (char)(tmp[1] >> 4);
			m_char[ii * 128 * 9 + 9 * j + 6] = (char)(tmp[1] >> 12);
			m_char[ii * 128 * 9 + 9 * j + 7] = (char)(tmp[1] >> 20);
			m_char[ii * 128 * 9 + 9 * j + 8] = (char)(tmp[1] >> 28);
		}
	}
}



/*************************************************
* Name:        unpack_polyvecm_q
*
* Description:  unpack m <- Rmq.
*
* Arguments:   - unsigned char *m_char: pointer to input array
*              - polyvecm *m: pointer to output vector m
**************************************************/
void unpack_polyvecm_q(unsigned char *m_char,
	polyvecm *m) 
{
	int ii, j;
	long long tmp[2];
	for (ii = 0; ii < M; ++ii)
	{
		for (j = 0; j < 128; ++j)
		{
			tmp[0] = (long long)m_char[ii * 128 * 9 + 9 * j + 0];
			tmp[0] |= (long long)m_char[ii * 128 * 9 + 9 * j + 1] << 8;
			tmp[0] |= (long long)m_char[ii * 128 * 9 + 9 * j + 2] << 16;
			tmp[0] |= (long long)m_char[ii * 128 * 9 + 9 * j + 3] << 24;
			tmp[0] |= ((long long)m_char[ii * 128 * 9 + 9 * j + 4] << 32)& (0xFFFFFFFFF);
			tmp[1] = (long long)m_char[ii * 128 * 9 + 9 * j + 4] >> 4;
			tmp[1] |= (long long)m_char[ii * 128 * 9 + 9 * j + 5] << 4;
			tmp[1] |= (long long)m_char[ii * 128 * 9 + 9 * j + 6] << 12;
			tmp[1] |= (long long)m_char[ii * 128 * 9 + 9 * j + 7] << 20;
			tmp[1] |= ((long long)m_char[ii * 128 * 9 + 9 * j + 8] << 28)& (0xFFFFFFFFF);

			m->vec[ii].coeffs[2 * j] = tmp[0] - Q_2;
			m->vec[ii].coeffs[2 * j + 1] = tmp[1] - Q_2;
		}
	}
}


/*************************************************
* Name:        pack_i
*
* Description:  Bit-pack i <- Rmq.
*
* Arguments:  - polyvecm *i: pointer to input vector i
*            - unsigned char *i_char: pointer to output array
**************************************************/
/**
void pack_i(polyvecm *i,
	unsigned char *i_char) 
{
	int ii, j;
	long long tmp[2];
	for (ii = 0; ii < M; ++ii)
	{
		for (j = 0; j < 128; ++j)
		{
			tmp[0] = i->vec[ii].coeffs[2 * j] + Q_2;
			tmp[1] = i->vec[ii].coeffs[2 * j + 1] + Q_2;
			i_char[ii * 128 * 9 + 9 * j + 0] = (char)tmp[0];
			i_char[ii * 128 * 9 + 9 * j + 1] = (char)(tmp[0] >> 8);
			i_char[ii * 128 * 9 + 9 * j + 2] = (char)(tmp[0] >> 16);
			i_char[ii * 128 * 9 + 9 * j + 3] = (char)(tmp[0] >> 24);
			i_char[ii * 128 * 9 + 9 * j + 4] = ((char)(tmp[0] >> 32)) | ((char)(tmp[1] << 4));
			i_char[ii * 128 * 9 + 9 * j + 5] = (char)(tmp[1] >> 4);
			i_char[ii * 128 * 9 + 9 * j + 6] = (char)(tmp[1] >> 12);
			i_char[ii * 128 * 9 + 9 * j + 7] = (char)(tmp[1] >> 20);
			i_char[ii * 128 * 9 + 9 * j + 8] = (char)(tmp[1] >> 28);
		}
	}
}
**/



/*************************************************
* Name:        unpack_i
*
* Description:  unpack i <- Rmq.
*
* Arguments:   - unsigned char *i_char: pointer to input array
*              - polyvecm *i: pointer to output vector i
**************************************************/
/**
void unpack_i(unsigned char *i_char,
	polyvecm *i) 
{
	int ii, j;
	long long tmp[2];
	for (ii = 0; ii < M; ++ii)
	{
		for (j = 0; j < 128; ++j)
		{
			tmp[0] = (long long)i_char[ii * 128 * 9 + 9 * j + 0];
			tmp[0] |= (long long)i_char[ii * 128 * 9 + 9 * j + 1] << 8;
			tmp[0] |= (long long)i_char[ii * 128 * 9 + 9 * j + 2] << 16;
			tmp[0] |= (long long)i_char[ii * 128 * 9 + 9 * j + 3] << 24;
			tmp[0] |= ((long long)i_char[ii * 128 * 9 + 9 * j + 4] << 32)& (0xFFFFFFFFF);
			tmp[1] = (long long)i_char[ii * 128 * 9 + 9 * j + 4] >> 4;
			tmp[1] |= (long long)i_char[ii * 128 * 9 + 9 * j + 5] << 4;
			tmp[1] |= (long long)i_char[ii * 128 * 9 + 9 * j + 6] << 12;
			tmp[1] |= (long long)i_char[ii * 128 * 9 + 9 * j + 7] << 20;
			tmp[1] |= ((long long)i_char[ii * 128 * 9 + 9 * j + 8] << 28)& (0xFFFFFFFFF);

			i->vec[ii].coeffs[2 * j] = tmp[0] - Q_2;
			i->vec[ii].coeffs[2 * j + 1] = tmp[1] - Q_2;
		}
	}
}
**/


/*************************************************
* Name:        pack_mpk
*
* Description:  Bit-pack mpk.
*
* Arguments:   - unsigned char *pkkem: point to input pk in kem
*              - polyveck *t: pointer to input vector t
*              - unsigned char *mpk: pointer to output array mpk
**************************************************/

void pack_mpk(unsigned char *pkkem,
	polyveck *t,
        unsigned char *mpk)
{
	unsigned int i;

	for (i = 0; i < SIZE_PKKEM; ++i)//pk_kem string
		mpk[i] = pkkem[i];
	mpk += SIZE_PKKEM;

	pack_polyveck_q(t, mpk);
}



/*************************************************
* Name:        unpack_mpk
*
* Description:  unpack mpk.
*
* Arguments:   - unsigned char *mpk: pointer to input array mpk
*             - unsigned char *pkkem: point to output pk in kem
*             - polyveck *t: pointer to output vector t
**************************************************/
void unpack_mpk(unsigned char *mpk,
	unsigned char *pkkem,
	polyveck *t)
{
	unsigned int i;

	for (i = 0; i < SIZE_PKKEM; ++i)
		pkkem[i] = mpk[i];
	mpk += SIZE_PKKEM;
    
	unpack_polyveck_q(mpk, t);
}


/*************************************************
* Name:        pack_msk
*
* Description:  Bit-pack msk.
*
* Arguments:   - unsigned char *skkem: point to input sk in kem
*              - polyvecl *s: pointer to input vector s
*              - unsigned char *msk: pointer to output array msk
**************************************************/
void pack_msk(unsigned char *skkem,
	polyvecl *s,
	unsigned char *msk)
{
	unsigned int i;

	for (i = 0; i < SIZE_SKKEM; ++i)//sk_kem string
		msk[i] = skkem[i];
	msk += SIZE_SKKEM;
    
	pack_polyvecl_eta(s, msk);
}



/*************************************************
* Name:        unpack_msk
*
* Description:  unpack msk.
*
* Arguments:   - unsigned char *msk: pointer to input array msk
*             - unsigned char *skkem: point to output sk in kem
*             - polyvecl *s: pointer to output vector s
**************************************************/
void unpack_msk(unsigned char *msk,
	unsigned char *skkem,
	polyvecl *s)
{
	unsigned int i;

	for (i = 0; i < SIZE_SKKEM; ++i)
		skkem[i] = msk[i];
	msk += SIZE_SKKEM;

	unpack_polyvecl_eta(msk, s);
}



/*************************************************
* Name:        pack_dpk
*
* Description:  Bit-pack dpk.
*
* Arguments:   - unsigned char *c: point to input C in kem
*              - polyveck *t: pointer to input vector t
*              - unsigned char *dpk: pointer to output array dpk
**************************************************/
void pack_dpk(unsigned char *c,
	polyveck *t,
	unsigned char *dpk)
{
	unsigned int i;

	for (i = 0; i < SIZE_CIPHER; ++i)//cipher string
		dpk[i] = c[i];
	dpk += SIZE_CIPHER;
        //printf("\npack t\n");
	pack_polyveck_q(t, dpk);
}



/*************************************************
* Name:        unpack_dpk
*
* Description:  unpack dpk.
*
* Arguments:   - unsigned char *dpk: pointer to input array dpk
*             - unsigned char *c: point to output C in kem
*              - polyveck *t: pointer to output vector t
**************************************************/
void unpack_dpk(unsigned char *dpk,
	unsigned char *c,
	polyveck *t)
{
	unsigned int i;

	for (i = 0; i < SIZE_CIPHER; ++i)
		c[i] = dpk[i];
	dpk += SIZE_CIPHER;
       // printf("\nunpack t\n");
	unpack_polyveck_q(dpk, t);
}



/*************************************************
* Name:        pack_sig
*
* Description:  Bit-pack sig.
*
* Arguments:   - poly *c: point to input c <- B\A6\C8
*              - unsigned int r: r in {zi}ri=1
*              - polyvecm* i: pointer to input i
*              - unsigned char *sig: pointer to output array sig
**************************************************/
void pack_sig(poly *c,
	unsigned int r,
	polyvecm* i,
	unsigned char *sig)
{
//        printf("we are in pack_sig now\n");
	unsigned int ii, j;
	long long signs, mask;


	/* Encode z*/
//        printf("encode z\n");

//	for (ii = 0; ii < r; ++ii)
//	{        
//                for (j = 0; j < PACK_Z_SIZE; ++j)
//                {
//                         sig[ii * PACK_Z_SIZE + j] = z[ii][j];
//                }
//	}

	sig += r * PACK_Z_SIZE;

	/* Encode I*/
//        printf("encode I\n");
	pack_polyvecm_q(i, sig);
	sig += PACK_I_SIZE;
	/* Encode c */
	signs = 0;
	mask = 1;
	for (ii = 0; ii < N / 8; ++ii) {
		sig[ii] = 0;
		for (j = 0; j < 8; ++j) {
			if (c->coeffs[8 * ii + j] != 0) {
				sig[ii] |= (1U << j);
				if (c->coeffs[8 * ii + j] == (Q - 1)) signs |= mask;
				mask <<= 1;
			}
		}
	}
	sig += N / 8;

	for (ii = 0; ii < 8; ++ii)
		sig[ii] = signs >> 8 * ii;
}



/*************************************************
* Name:        unpack_sig
*
* Description:  unpack sig.
*
* Arguments:   - unsigned char *sig: pointer to input array sig
*             - poly *c: point to output c <- B\A6\C8
*              - unsigned int r: r in {zi}ri=1
*              - polyvecm* i: pointer to output i
**************************************************/
int unpack_sig(unsigned char *sig,
	poly *c,
	unsigned int r,
	polyvecm* i)
{
	unsigned int ii, j;
	long long signs;
	/* Decode z*/

//	for (ii = 0; ii < r; ++ii)
//	{        
//               for (j = 0; j < PACK_Z_SIZE; ++j)
//               {
//                      z[ii][j] = sig[ii * PACK_Z_SIZE + j];
//               }
//	}
	sig += r * PACK_Z_SIZE;

	/* Decode I */
	unpack_polyvecm_q(sig, i);
	sig += PACK_I_SIZE;
	/* Decode c */
	for (ii = 0; ii < N; ++ii)
		c->coeffs[ii] = 0;

	signs = 0;
	for (ii = 0; ii < 8; ++ii)
		signs |= (long long)sig[N / 8 + ii] << 8 * ii;

	/* Extra sign bits are zero for strong unforgeability */
	if (signs >> 60)
		return -1;

	for (ii = 0; ii < N / 8; ++ii) {
		for (j = 0; j < 8; ++j) {
			if ((sig[ii] >> j) & 0x01) {
				c->coeffs[8 * ii + j] = 1;
				c->coeffs[8 * ii + j] ^= -(signs & 1) & (1 ^ (Q - 1));
				signs >>= 1;
			}
		}
	}
        return 0;
}




