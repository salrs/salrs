#include <stdio.h>
#include <string.h>
#include "../src/cpucycles.h"
#include "speed.h"
#include "../src/randombytes.h"
#include "../src/params_salrs.h"
#include "../src/salrs_main.h"
#include "../src/kyber_all.h"
#include "../src/polyvec_salrs.h"

#define MLEN 59
#define NTESTS 1000
#define RSIZE_MAX 35
#define SIG_SIZE RSIZE_MAX*4000
#define round 1000

unsigned long long timing_overhead;
#ifdef DBENCH
unsigned long long *tred, *tadd, *tmul, *tround, *tsample, *tpack, *tshake;
#endif

int main(void)
{
  double time, t_setup_max = 0,t_setup_min = 100000, t_publiccheck_max = 0, t_publiccheck_min = 100000;
  int RSIZE[5] = {1, 3, 5, 10, 20};
  unsigned int tmp, c_masterkeygen = 0, c_derivedkeygen = 0, c_ownercheck = 0, c_publiccheck = 0, c_sign = 0, c_verify = 0,  t_masterkeygen_max = 0, t_derivedkeygen_max = 0, t_ownercheck_max = 0, t_sign_max = 0, t_verify_max = 0,  t_masterkeygen_min = 100000, t_derivedkeygen_min = 100000, t_ownercheck_min = 100000,t_sign_min = 100000, t_verify_min = 100000;
  int c_rej_max = 0, c_rej_min = 1000, i, ii, k, c_rej = 0;
  int ret;
  unsigned char m[MLEN];
  //unsigned char m2[MLEN];
  unsigned long long crej[NTESTS * RSIZE_MAX], tsetup[round], tmasterkeygen[round], tderivedkeygen[round], townercheck[round], tpubliccheck[round], tsign[NTESTS * RSIZE_MAX], tverify[NTESTS * RSIZE_MAX];
  //unsigned long long tkeygen[NTESTS * RSIZE_MAX];
  unsigned char mpk[RSIZE_MAX][SIZE_MPK];
  unsigned char msvk[RSIZE_MAX][SIZE_SKKEM];
  unsigned char mssk[RSIZE_MAX][PACK_S_SIZE];
  unsigned char ring[RSIZE_MAX][SIZE_DPK];
  unsigned char sig[RSIZE_MAX][SIG_SIZE];
  unsigned char seed[SIZE_PKKEM + SIZE_SKKEM + PACK_S_SIZE];
  unsigned char key_image[PACK_I_SIZE];
  //unsigned char sm[SIG_SIZE];
  //polyvecl z[RSIZE_MAX + 5];
  //polyvecl z2[RSIZE_MAX + 5];
#ifdef DBENCH
  unsigned long long t[7][NTESTS], dummy;

  memset(t, 0, sizeof(t));
  tred = tadd = tmul = tround = tsample = tpack = tshake = &dummy;
#endif

  timing_overhead = cpucycles_overhead();

//setup()
  for (ii = 0; ii < round; ++ii)
{  
        tsetup[ii] = cpucycles_start();
        Setup();
        tsetup[ii] = cpucycles_stop() - tsetup[ii] - timing_overhead;
        time = (double)(tsetup[ii])/2600000;
        if (time > t_setup_max){t_setup_max = time;}
        if (time < t_setup_min){t_setup_min = time;}
}
  //printf("setup_time:%f msecs\n\n", time);
  print_results("setup:", tsetup, round);
  printf("max:%f msecs\n", t_setup_max);
  printf("min:%f msecs\n\n", t_setup_min);

//masterkeygen()
  for (ii = 0; ii < round; ++ii)
  {
        
        tmasterkeygen[c_masterkeygen] = cpucycles_start();
        //printf("\norder in test:%d\n",ii);
        MasterSeedGen(seed);
        MasterKeyGen(seed, mpk[0], msvk[0], mssk[0]);
	//DerivedPublicKeyGen(mpk[0], ring[0]); 
        tmasterkeygen[c_masterkeygen] = cpucycles_stop() - tmasterkeygen[c_masterkeygen] - timing_overhead; 
        time = (double)(tmasterkeygen[c_masterkeygen])/2600000;
        if (time > t_masterkeygen_max){t_masterkeygen_max = time;}
        if (time < t_masterkeygen_min){t_masterkeygen_min = time;}
        c_masterkeygen++;
  }
  print_results("masterkeygen:", tmasterkeygen, round);
  printf("max:%d msecs\n", t_masterkeygen_max);
  printf("min:%d msecs\n\n", t_masterkeygen_min);

//derivedkeygen() && ownercheck() && publiccheck()
  for (i = 0; i < round; ++i)
  {
                MasterSeedGen(seed);
                MasterKeyGen(seed, mpk[0], msvk[0], mssk[0]);
                tderivedkeygen[c_derivedkeygen] = cpucycles_start();
		DerivedPublicKeyGen(mpk[0], ring[0]); 
                tderivedkeygen[c_derivedkeygen] = cpucycles_stop() - tderivedkeygen[c_derivedkeygen] - timing_overhead;
                time = (double)(tderivedkeygen[c_derivedkeygen])/2600000;
                if (time > t_derivedkeygen_max){t_derivedkeygen_max = time;}
                if (time < t_derivedkeygen_min){t_derivedkeygen_min = time;}
                c_derivedkeygen++;

                townercheck[c_ownercheck] = cpucycles_start();
		ret = DerivedPublicKeyOwnerCheck(ring[0], mpk[0], msvk[0]);
		if (ret == 0) {
			printf("\nDpk Owner Check Wrong\n\n");
			return -1;
		}
                townercheck[c_ownercheck] = cpucycles_stop() - townercheck[c_ownercheck] - timing_overhead;
                time = (double)(townercheck[c_ownercheck])/2600000;
                if (time > t_ownercheck_max){t_ownercheck_max = time;}
                if (time < t_ownercheck_min){t_ownercheck_min = time;}
                c_ownercheck++;

                tpubliccheck[c_publiccheck] = cpucycles_start();
		ret = DerivedPublicKeyPublicCheck(ring[0]);
		if (ret == 0) {
			printf("\nDpk Public Check Wrong\n\n");
			return -1;
		}
                tpubliccheck[c_publiccheck] = cpucycles_stop() - tpubliccheck[c_publiccheck] - timing_overhead;
                time = (double)(tpubliccheck[c_publiccheck])/2600000;
                if (time > t_publiccheck_max){t_publiccheck_max = time;}
                if (time < t_publiccheck_min){t_publiccheck_min = time;}
                c_publiccheck++;
  }
  print_results("derivedkeygen:", tderivedkeygen, round);
  printf("max:%d msecs\n", t_derivedkeygen_max);
  printf("min:%d msecs\n\n", t_derivedkeygen_min);
  print_results("ownercheck:", townercheck, round);
  printf("max:%d msecs\n", t_ownercheck_max);
  printf("min:%d msecs\n\n", t_ownercheck_min);
  print_results("publiccheck:", tpubliccheck, round);
  printf("max:%f msecs\n", t_publiccheck_max);
  printf("min:%f msecs\n\n", t_publiccheck_min);
  
//sign() && verify() && link()
for (k = 0; k < 5; ++k)
{
  t_sign_max = 0;
  t_verify_max = 0;
  t_sign_min = 100000;
  t_verify_min = 100000; 
  c_rej_max = 0;
  c_rej_min = 100000;
  c_rej = 0;
  c_sign = 0;
  c_verify = 0;
  for(i = 0; i < NTESTS / RSIZE[k]; ++i) {
    randombytes(m, MLEN);
/**        printf("\nMessage in binary:\n");
        for (ii = 0; ii < MLEN; ++ii)
        {
                tmp = (int)m[ii];
                for (j = 0; j < 8; ++j)
                {
                        printf("%d", tmp % 2);
                        tmp = tmp / 2;
                }
                printf(" ");
        }
        printf("\n");
**/
	
	for (ii = 0; ii < RSIZE[k]; ++ii)
	{
                MasterSeedGen(seed);
                MasterKeyGen(seed, mpk[ii], msvk[ii], mssk[ii]);
		DerivedPublicKeyGen(mpk[ii], ring[ii]); 
	}


#ifdef DBENCH
    tred = t[0] + i;
    tadd = t[1] + i;
    tmul = t[2] + i;
    tround = t[3] + i;
    tsample = t[4] + i;
    tpack = t[5] + i;
    tshake = t[6] + i;
#endif
/**        printf("\nOwner\n");
	for (ii = 0; ii < RSIZE[k]; ++ii)
	{
                printf("Owner_test_%d\n", ii);
		ret = derived_public_key_owner_check_scheme(ring[ii], msk[ii], mpk[ii]);
		if (ret == 0) {
			printf("\nDpk Owner Check Wrong\n\n");
			return -1;
		}
	}
        printf("\nDpk owner check passed\n\n");
        printf("Dpk public\n");
	for (ii = 0; ii < RSIZE[k]; ++ii)
	{
                printf("Dpk_public_test_%d\n", ii);
		ret = derived_public_key_public_check_scheme(ring[ii]);
		if (ret == 0) {
			printf("\nDpk Public Check Wrong\n\n");
			return -1;
		}
	}
        printf("\nDpk public check passed\n\n");
**/
//        printf("Sign\n");
	for (ii = 0; ii < RSIZE[k]; ++ii)
	{
//           printf("Now we are in sign round %d\n", c_sign);
//           printf("Sign_test_%d\n",ii);
           tsign[c_sign] = cpucycles_start();
	   ret = Sign(m, MLEN, ring, RSIZE[k], ring[ii], mpk[ii], msvk[ii], mssk[ii], sig[ii], key_image);
           tsign[c_sign] = cpucycles_stop() - tsign[c_sign] - timing_overhead;
//           printf("\nsign_end\n");
           if (ret == -1){printf("Sign failed\n");}
            time = (double)(tsign[c_sign])/2600000;
            if (time > t_sign_max){t_sign_max = time;}
            if (time < t_sign_min){t_sign_min = time;}
            crej[c_rej] = ret;
            if (ret > c_rej_max){c_rej_max = ret;}
            if (ret < c_rej_min){c_rej_min = ret;}
            c_rej++;
            c_sign++;
	}
//#ifdef DBENCH
//    tred = tadd = tmul = tround = tsample = tpack = tshake = &dummy;
//#endif
//        printf("\nSign check passed\n\n");
	for (ii = 0; ii < RSIZE[k]; ++ii)
	{
//         printf("Verify_test_%d\n", ii);
          tverify[c_verify] = cpucycles_start();
	   ret = Verify(m, MLEN, ring, RSIZE[k], sig[ii], key_image);
       tverify[c_verify] = cpucycles_stop() - tverify[c_verify] - timing_overhead;


       if(ret == 0) {
         printf("\nVerification failed\n\n");
         return -1;
          }  
            time = (double)(tverify[c_verify])/2600000;
            if (time > t_verify_max){t_verify_max = time;}
            if (time < t_verify_min){t_verify_min = time;}
            c_verify++;
	} 
//     printf("\nVerify check passed\n\n");

/**    printf("Other_tests:\n\n");
    randombytes(m2, MLEN);
	randombytes(sm, SIG_SIZE);
	ret = verify_salrs(m2, MLEN, ring, RSIZE, z, sig[ii]);
    if(ret == 1) {
      printf("Trivial forgeries possible\n");
      return -1;
    }
        printf("No trivial forgeries possible\n");
**/
        ret = Link(sig[0], m, MLEN, ring, RSIZE[k], sig[0], m, MLEN, ring, RSIZE[k]);
	if (ret == 0) {
//		printf("no Double Spend\n");
		return -1;
	}
/**        ret = link_salrs(sig[0], m, MLEN, ring, RSIZE[k], sig[1], m, MLEN, ring, RSIZE[k]);
	if (ret == 1) {
		printf("Double Spend\n");
		return -1;
	}
        printf("No double spend\n"); 
        printf("\nOther tests passed\n");
        printf("\n\n\n");
**/
  }
  tmp = 0;
  for (i = 0; i < c_rej; ++i)
  {
      tmp += crej[i];
  }
  time = (double)(tmp)/c_rej;

  printf("\n\nthe size of ring is %d\n\n", RSIZE[k]);
  printf("rejection max:%d, rejection min:%d, rejection average:%f\n\n", c_rej_max, c_rej_min, time);
//  print_results("keygen:", tkeygen, NTESTS * RSIZE);
  print_results("sign: ", tsign, NTESTS / RSIZE[k] * RSIZE[k]);
  printf("max:%d msecs\n", t_sign_max);
  printf("min:%d msecs\n\n", t_sign_min);
  print_results("verify: ", tverify, NTESTS / RSIZE[k] * RSIZE[k]);
  printf("max:%d msecs\n", t_verify_max);
  printf("min:%d msecs\n\n", t_verify_min);
}

#ifdef DBENCH
  print_results("modular reduction:", t[0], NTESTS);
  print_results("addition:", t[1], NTESTS);
  print_results("multiplication:", t[2], NTESTS);
  print_results("rounding:", t[3], NTESTS);
  print_results("rejection sampling:", t[4], NTESTS);
  print_results("packing:", t[5], NTESTS);
  print_results("SHAKE:", t[6], NTESTS);
#endif

  return 0;
}
