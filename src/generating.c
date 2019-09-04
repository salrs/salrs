#include <stdint.h>
#include "fips202.h"
#include "params_salrs.h"
#include "randombytes.h"
#include "polyvec_salrs.h"
#include "hash_func.h"
#include "packing_salrs.h"
#include "kyber_all.h"
#include "generating.h"

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [-(Q-1)/2,(Q-1)/2] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - long long *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_uniform(long long *a,
                                unsigned int len,
                                const unsigned char *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  long long t;
  //DBENCH_START();

  ctr = pos = 0;
  while (ctr < len && pos + 5 <= buflen)
  {
    t = buf[pos++];
    t |= (long long)buf[pos++] << 8;
    t |= (long long)buf[pos++] << 16;
    t |= (long long)buf[pos++] << 24;
    t |= (long long)(buf[pos++] >> 4) << 32;
    t &= 0xFFFFFFFFF;

    if (t < Q)
      a[ctr++] = t - (Q - 1) / 2;
  }

  //DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-ETA, ETA] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - long long *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_eta(long long *a,
                            unsigned int len,
                            const unsigned char *buf,
                            unsigned int buflen)
{
  unsigned int ctr, pos;
  long long t0, t1;
  //DBENCH_START();

  ctr = pos = 0;
  while (ctr < len && pos < buflen)
  {
    t0 = buf[pos] & 0x07;
    t1 = buf[pos++] >> 5;

    if (t0 <= 2 * ETA)
      a[ctr++] = ETA - t0;
    if (t1 <= 2 * ETA && ctr < len)
      a[ctr++] = ETA - t1;
  }

  //DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        rej_gamma
*
* Description: Sample uniformly random coefficients
*              in [-GAMMA, GAMMA] by performing rejection sampling
*              using array of random bytes.
*
* Arguments:   - long long *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_gamma(long long *a,
                              unsigned int len,
                              const unsigned char *buf,
                              unsigned int buflen)
{
  unsigned int ctr, pos;
  long long t;
  //DBENCH_START();

  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen)
  {
    t = buf[pos++];
    t |= (long long)buf[pos++] << 8;
    t |= (long long)(buf[pos++] >> 3) << 16;
    t &= 0x1FFFFF;

    if (t <= 2 * GAMMA)
      a[ctr++] = GAMMA - t;
  }

  //DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        rej_gmte
*
* Description: Sample uniformly random coefficients
*              in [-GAMMA+2*THETA*ETA, GAMMA-2*THETA*ETA] by performing rejection sampling
*              using array of random bytes.
*
* Arguments:   - long long *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_gmte(long long *a,
                             unsigned int len,
                             const unsigned char *buf,
                             unsigned int buflen)
{
  unsigned int ctr, pos;
  long long t;
  //DBENCH_START();

  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen)
  {
    t = buf[pos++];
    t |= (long long)buf[pos++] << 8;
    t |= (long long)(buf[pos++] >> 3) << 16;
    t &= 0x1FFFFF;

    if (t <= GAMMA - 2 * THETA * ETA)
      a[ctr++] = GAMMA - 2 * THETA * ETA - t;
  }

  //DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(Q-1)/2,(Q-1)/2] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char cstr[]: byte array with seed of length
*                                            CSTRSIZE
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void poly_uniform(poly *a,
                  const unsigned char seed[SEEDBYTES],
                  uint16_t nonce)
{
  unsigned int i, ctr, off;
  unsigned int nblocks = (UNKNOWNBYTES_A + STREAM128_BLOCKBYTES) / STREAM128_BLOCKBYTES;
  unsigned int buflen = nblocks * STREAM128_BLOCKBYTES;
  unsigned char buf[buflen + 2];
  stream128_state state;

  stream128_init(&state, seed, nonce);
  stream128_squeezeblocks(buf, nblocks, &state);

  ctr = rej_uniform(a->coeffs, N, buf, buflen);

  while (ctr < N)
  {
    off = buflen % 5;
    for (i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];

    buflen = STREAM128_BLOCKBYTES + off;
    stream128_squeezeblocks(buf + off, 1, &state);
    ctr += rej_uniform(a->coeffs + ctr, N - ctr, buf, buflen);
  }
}

/*************************************************
* Name:        poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-ETA,ETA] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            ETASEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void poly_uniform_eta(poly *a,
                      const unsigned char seed[ETASEEDBYTES],
                      uint16_t nonce)
{
  unsigned int ctr;
  unsigned int nblocks = ((N / 2 * 8U) / (2 * ETA + 1) + STREAM128_BLOCKBYTES) / STREAM128_BLOCKBYTES;
  unsigned int buflen = nblocks * STREAM128_BLOCKBYTES;
  unsigned char buf[buflen];
  stream128_state state;

  stream128_init(&state, seed, nonce);
  stream128_squeezeblocks(buf, nblocks, &state);

  ctr = rej_eta(a->coeffs, N, buf, buflen);

  while (ctr < N)
  {
    stream128_squeezeblocks(buf, 1, &state);
    ctr += rej_eta(a->coeffs + ctr, N - ctr, buf, STREAM128_BLOCKBYTES);
  }
}

/*************************************************
* Name:        poly_uniform_gamma
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-GAMMA, GAMMA] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            GAMMASEEDBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
void poly_uniform_gamma(poly *a,
                        const unsigned char seed[GAMMASEEDSIZE],
                        uint16_t nonce)
{
  unsigned int i, ctr, off;
  unsigned int nblocks = (UNKNOWNBYTES_GAMMA + STREAM256_BLOCKBYTES) / STREAM256_BLOCKBYTES;
  unsigned int buflen = nblocks * STREAM256_BLOCKBYTES;
  unsigned char buf[buflen + 4];
  stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, nblocks, &state);

  ctr = rej_gamma(a->coeffs, N, buf, buflen);

  while (ctr < N)
  {
    off = buflen % 3;
    for (i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];

    buflen = STREAM256_BLOCKBYTES + off;
    stream256_squeezeblocks(buf + off, 1, &state);
    ctr += rej_gamma(a->coeffs + ctr, N - ctr, buf, buflen);
  }
}

/*************************************************
* Name:        poly_uniform_gmte
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-GAMMA+2*THETA*ETA, GAMMA-2*THETA*ETA] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            GMTESEEDBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
void poly_uniform_gmte(poly *a,
                        const unsigned char seed[GMTESEEDSIZE],
                        uint16_t nonce)
{
  unsigned int i, ctr, off;
  unsigned int nblocks = (UNKNOWNBYTES_GMTE + STREAM256_BLOCKBYTES) / STREAM256_BLOCKBYTES;
  unsigned int buflen = nblocks * STREAM256_BLOCKBYTES;
  unsigned char buf[buflen + 4];
  stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, nblocks, &state);

  ctr = rej_gmte(a->coeffs, N, buf, buflen);

  while (ctr < N)
  {
    off = buflen % 3;
    for (i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];

    buflen = STREAM256_BLOCKBYTES + off;
    stream256_squeezeblocks(buf + off, 1, &state);
    ctr += rej_gmte(a->coeffs + ctr, N - ctr, buf, buflen);
  }
}

/*************************************************
* Name:        expand_matA
*
* Description: Implementation of expandA. 
*             generate a k * l matrix with polynomial elements 
*             with coefficients belonging to [-(Q-1)/2,(Q-1)/2] using cstr
* Arguments:    - polyvecl mat[K]: output k*l matrix A
*               - const unsigned char cstr[]: byte array with seed of length
*                                            CSTRSIZE
**************************************************/
void expand_matA(polyvecl matA[K])
{
  unsigned int i, j;
  unsigned char seedbuf[CSTRSIZE] = cstr;
  for (i = 0; i < K; ++i)
    for (j = 0; j < L; ++j)
      poly_uniform(&matA[i].vec[j], seedbuf, (i << 8) + j);
}

/*************************************************
* Name:        expand_V
*
* Description: Implementation of expandV. 
*             generate a vector of length l with polynomial elements 
*             with coefficients belonging to[-ETA,ETA] using stream of random bytes
* Arguments:   - unsigned char Kyber_k[KYBER_SYMBYTES]: byte array containing seed k in
*                                                KYBER where KYBER_SYMBYTES = 32
*                                                is the length of k in KYBER
*             - polyvecl *V: pointer to output vector V
**************************************************/
void expand_V(unsigned char Kyber_k[KYBER_SYMBYTES], polyvecl *V)
{
  unsigned int i;
  for (i = 0; i < L; ++i){
    poly_uniform_eta(&V->vec[i], Kyber_k, i);
}
}

/*************************************************
* Name:        generate_L_eta
*
* Description: generate a vector of length l with polynomial elements 
*             with coefficients belonging to [-ETA,ETA] 
* Arguments:   - polyvecl *s: pointer to output polynomial
**************************************************/
void generate_L_eta(polyvecl *s)
{
  unsigned int i;
  unsigned char seedbuf[3 * LETASEEDSIZE];
  randombytes(seedbuf, 3 * LETASEEDSIZE);
  for (i = 0; i < L; ++i){
    poly_uniform_eta(&s->vec[i], seedbuf, i);
   }
}

/*************************************************
* Name:        generate_gamma
*
* Description: generate a vector of length l with polynomial elements 
*             with coefficients belonging to[-GAMMA, GAMMA]
* Arguments:   - polyvecl *s: pointer to output polynomial
**************************************************/
void generate_L_gamma(polyvecl *s)
{
  unsigned int i;
  unsigned char seedbuf[GAMMASEEDSIZE];
  randombytes(seedbuf, GAMMASEEDSIZE);
  for (i = 0; i < L; ++i){
    poly_uniform_gamma(&s->vec[i], seedbuf, i);
  }
}

/*************************************************
* Name:        generate_gamma_sub_to_theta_eta
*
* Description: generate a vector of length l with polynomial elements 
*             with coefficients belonging to [-GAMMA+2*THETA*ETA, GAMMA-2*THETA*ETA]
* Arguments:   - polyvecl *s: pointer to output polynomial
**************************************************/
void generate_L_gamma_sub_to_theta_eta(polyvecl *s)
{
  unsigned int i;
  unsigned char seedbuf[GMTESEEDSIZE];
  randombytes(seedbuf, GMTESEEDSIZE);
  for (i = 0; i < L; ++i){
    poly_uniform_gmte(&s->vec[i], seedbuf, i);
  }
}

/*************************************************
* Name:        Hm
*
* Description:   Implementation of Hm. 
*             generate a m * l matrix with polynomial elements 
*             with coefficients belonging to [-(Q-1)/2,(Q-1)/2] using t as the seed
* Arguments:   - polyveck * t: pointer to input vector t
*             - polyvecl H[m]: output matrix H
**************************************************/
void Hm(polyveck *t, polyvecl H[M])
{
  unsigned int i, j;
  unsigned char seedpack[PACK_T_SIZE],seedbuf[HMSEEDSIZE];
  pack_polyveck_q(t,seedpack);
  shake256(seedbuf,HMSEEDSIZE,seedpack,PACK_T_SIZE);
  for (i = 0; i < M; ++i){
    for (j = 0; j < L; ++j){
      poly_uniform(&H[i].vec[j], seedbuf, (i << 8) + j);
    }
  }
}


/*************************************************
* Name:        H_theta
*
* Description:   Implementation of H_theta,which is inside-out shuffle algorithm
*             a function to generate c which has 256 coefficients
*              , where 60 of them are 1/-1 and the rest are 0.
* Arguments:   - unsigned char * m: point to input message
*             - unsigned int mlen: the length of message
*             - unsigned char **Ring: point to Ring = (dpk1, dpk2.....dpkr)
*             - unsigned int r:r in Ring = (dpk1, dpk2.....dpkr)
*             - polyveck *w:point to input vector w
*             - polyvecm *v:point to input vector v
*             - polyvecm *I:point to input vector I
*             - poly* c: pointer to output c
**************************************************/
void H_theta(unsigned char *m,
             unsigned int mlen,
             unsigned char (*Ring)[SIZE_DPK],
             unsigned int r,
             polyveck *w,
             polyvecm *v,
             polyvecm *I,
             poly *c)
{
  unsigned int i, b, pos;
  uint64_t signs;
  unsigned int inbuf_len = SHAKE256_RATE + r * SIZE_DPK + PACK_T_SIZE + 2 * PACK_I_SIZE;
  unsigned char inbuf[inbuf_len];
  unsigned char outbuf[SHAKE256_RATE];
  keccak_state state;
  unsigned int count = 0;

  shake256(inbuf, SHAKE256_RATE, m, mlen);
  count = SHAKE256_RATE;
  for (i = 0; i < r; ++i)
  {
//    flag = 1;
    for (int j = 0; j < SIZE_DPK; j++)
    {
      inbuf[count++] = Ring[i][j];
    }
  }
  pack_polyveck_q(w, inbuf + count);
  count += PACK_T_SIZE;
  pack_polyvecm_q(v, inbuf + count);
  count += PACK_I_SIZE;
  pack_polyvecm_q(I, inbuf + count);
  count += PACK_I_SIZE;

  shake256_absorb(&state, inbuf, inbuf_len);
  shake256_squeezeblocks(outbuf, 1, &state);

  signs = 0;
  for (i = 0; i < 8; ++i)
    signs |= (uint64_t)outbuf[i] << 8 * i;

  pos = 8;

  for (i = 0; i < N; ++i)
    c->coeffs[i] = 0;

  for (i = 196; i < 256; ++i)
  {
    do
    {
      if (pos >= SHAKE256_RATE)
      {
        shake256_squeezeblocks(outbuf, 1, &state);
        pos = 0;
      }

      b = outbuf[pos++];
    } while (b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1;
    c->coeffs[b] ^= -(signs & 1) & (1 ^ (Q - 1));
    signs >>= 1;
  }
  //for (i = 0; i < N; ++i)
  //{
  //  if(c->coeffs[i] == (Q - 1))
  //   {
  //       c->coeffs[i] = -1;
  //   } 
  //}
}
