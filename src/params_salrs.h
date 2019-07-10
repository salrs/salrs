#ifndef PARAMS_SALRS_H
#define PARAMS_SALRS_H

#define N 256
#define L 5
#define K 3
#define M 1
#define THETA 60
#define ETA 3
#define GAMMA 699453
#define GAMMA_MINUS_TWO_ETA_THETA 699093
#define KYBER_SYMBYTES 32
#define LETASEEDSIZE 32
#define ETASEEDBYTES 32
#define GAMMASEEDSIZE 48
#define GMTESEEDSIZE 48
#define SEEDBYTES 32
#define HMSEEDSIZE 32

#define Q 34360786961LL
#define Q_2 17180393480LL //(Q - 1)/2
#define R1 -16915236577LL
#define R2 -8376412603LL
#define R3 -3354919284LL
#define R4 11667088462LL
#define R5 -12474372669LL
#define R6 -3077095668LL
#define R7 14301820476LL
#define R8 -1LL
#define R9 16915236577LL
#define R10 8376412603LL
#define R11 3354919284LL
#define R12 -11667088462LL
#define R13 12474372669LL
#define R14 3077095668LL
#define R15 -14301820476LL
#define R16 1LL

#define PACK_T_SIZE 3456
#define PACK_S_SIZE 480
#define PACK_Z_SIZE 3520
#define PACK_I_SIZE 1152

#define UNKNOWNBYTES_GMTE 1000
#define UNKNOWNBYTES_GAMMA 1000
#define UNKNOWNBYTES_A 1000

#define SIZE_MPK 4544
#define SIZE_PKKEM 1088
#define SIZE_MSK 2880
#define SIZE_SKKEM 2400
#define SIZE_DPK 4608
#define SIZE_CIPHER 1152

#define cstr "today_is_a_good_day_today_is_a_good_day_today_is_a_good_day"
#define CSTRSIZE sizeof(cstr)

#define KYBER_N 256
#define KYBER_Q 7681
#define KYBER_SYMBYTES 32   /* size in bytes of shared key, hashes, and seeds */


#endif // !PARAMS_SALRS.H
