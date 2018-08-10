/*
 *  Copyright 2017 Zhenfei Zhang @ onboard security
 *
 *  This file is part of pqNTRUSign signature scheme with bimodal
 *  Gaussian sampler (Gaussian-pqNTRUSign).
 *
 *  This software is released under GPL:
 *  you can redistribute it and/or modify it under the terms of the
 *  GNU General Public License as published by the Free Software
 *  Foundation, either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  You should have received a copy of the GNU General Public License.
 *  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include "blake2.h"


#include "param.h"
#include "poly/poly.h"
#include "pqNTRUSign.h"
#include "rng/fastrandombytes.h"
#include "rng/crypto_hash_sha512.h"
#include "api.h"

/*
 * uncomment VERBOSE to get extra information for testing
 * #define VERBOSE
 */


unsigned char   rndness[32] = "source of randomness";
unsigned char   msg[32]     = "nist submission";

int get_len(unsigned char *c)
{
    int len = 0;
    while(c[len]!='\0')
        len++;
    return len;
}


uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int test(PQ_PARAM_SET *param)
{

    int64_t   *f, *g, *g_inv, *h, *buf, *sig, *mem;


    uint64_t startc, endc, signtime = 0, verifytime = 0;
    clock_t start, end;
    double cpu_time_used1;
    double cpu_time_used2;
    int i =0;
    int counter = 0;

    unsigned char   *msg;
    unsigned char   *seed   = (unsigned char*) "nist submission";
    size_t          msg_len = 64;

    /* memory to store keys/msgs/ctx */
    mem = malloc (sizeof(int64_t)*param->padded_N * 7);
    /* buffer */
    buf = malloc (sizeof(int64_t)*param->padded_N * 11);
    /* message to be signed */
    msg = malloc (sizeof(unsigned char)*msg_len);


    if (!mem || !buf || !msg)
    {
        printf("malloc error!\n");
        return -1;
    }

    crypto_hash_sha512(msg, seed, msg_len);

    memset(mem, 0, sizeof(int64_t)*param->padded_N * 7);
    memset(buf, 0, sizeof(int64_t)*param->padded_N * 11);


    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;
    sig     = h     + param->padded_N*2;


    /* generate a set of keys */
    printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");
    printf("testing parameter set %s \n", param->name);


    printf("begin a single signing procedure\n");




    memset(buf, 0, sizeof(int64_t)*param->padded_N * 4);
    keygen(f,g,g_inv,h,buf,param);

#ifdef VERBOSE
    printf("start key generation\n");
    printf("f:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,",(long long)f[i]);
    printf("\ng:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,", (long long)g[i]);
    printf("\ng_inv:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,",(long long)g_inv[i]);
    printf("\nh:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,",(long long)h[i]);
    printf("\n");
    printf("finished key generation\n");
    printf("=====================================\n");
#endif


    /* generate a message vector to sign */
//    pol_gen_flat(msg, param->N, param->d);
//    pol_gen_flat(msg+param->N, param->N, param->d);

    /* sign the msg */
    printf("now signing a message\n");

#ifdef VERBOSE
    for (i=0;i<param->N;i++)
        printf("%lld,",(long long)msg[i]);
    printf("\n");
    for (;i<param->padded_N*2;i++)
        printf("%lld,",(long long)msg[i]);
    printf("\n");
#endif

    memset(buf, 0, sizeof(int64_t)*param->N * 11);
    sign(sig, msg, msg_len,f,g,g_inv,h,buf,param);
#ifdef VERBOSE
    printf("the signature is:\n");
    for (i=0;i<param->N;i++)
        printf("%lld,",(long long)sig[i]);
    printf("\n");
#endif
    printf("=====================================\n");

    printf("now verifying the signature: 0 for valid, -1 for invalid:   ");
    /* verifying the signature */
    memset(buf, 0, sizeof(int64_t)*param->N * 7);
    printf("%d \n", verify(sig, msg, msg_len, h,buf,param));
    printf("=====================================\n");

    printf("benchmark with signing a set of messages\n");

    for (i=0;i<100;i++)
    {
        /* generate a new message to sign */
        crypto_hash_sha512(msg, msg, msg_len);

        /* sign the msg */
        memset(buf, 0, sizeof(int64_t)*param->N * 10);
        start = clock();
        startc = rdtsc();
        counter += sign(sig, msg,msg_len, f,g,g_inv,h,buf,param);
        endc = rdtsc();
        end = clock();
        cpu_time_used1 += (end-start);
        signtime += (endc-startc);

        /* verifying the signature */
        memset(buf, 0, sizeof(int64_t)*param->N * 7);
        startc = rdtsc();
        start = clock();

        if(verify(sig, msg,msg_len, h,buf,param)!=0)
            printf("%d verification error\n", i);
        end = clock();
        cpu_time_used2 += (end-start);
        endc = rdtsc();
        verifytime += (endc-startc);
    }
    printf("it takes %d samples to generate %d number of signatures!\n", counter, i);
    printf("average signing time: %f clock cycles or %f seconds!\n", (double)signtime/i, cpu_time_used1/i/CLOCKS_PER_SEC);
    printf("average verification time:  %f clock cycles or %f seconds!\n", (double)verifytime/i, cpu_time_used2/i/CLOCKS_PER_SEC);

    free(msg);
    free(mem);
    free(buf);
	return 0;
}

int test_basic(void)
{
    uint16_t i;
    PQ_PARAM_SET_ID plist[] =
    {
        uniform_512_107,
        uniform_761_107,
        Gaussian_512_107,
        Gaussian_761_107,
    };
    size_t numParams = sizeof(plist)/sizeof(PQ_PARAM_SET_ID);

    for(i = 0; i<numParams; i++)
    {
      test(pq_get_param_set_by_id(plist[i]));
    }

    rng_cleanup();
    return 0;

}

int test_nist_api()
{


    unsigned char       *sig;
    unsigned char       *pk, *sk;
    unsigned long long  siglen;
    unsigned long long  mlen;

    pk  = malloc(sizeof(unsigned char)* 5000);
    sk  = malloc(sizeof(unsigned char)* 10000);
    sig = malloc(sizeof(unsigned char)* 5000);


    mlen = get_len(msg);


    /* generate a set of keys */
    printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");
    printf("testing NIST API\n");


    int i=0;
    crypto_sign_keypair(pk, sk);

    printf("key generated, public key (first 32 bytes):\n");

    for(i=0;i<32;i++)
        printf("%d,",pk[i]);
    printf("\n");

    printf("and secret key (first 32 bytes):\n");
    for(i=0;i<32;i++)
        printf("%d,",sk[i]);
    printf("\n");

    printf("begin a single signing procedure\n");

    crypto_sign(sig, &siglen, msg, mlen, sk);

    printf("signature of length %d:\n", (int)siglen);
    for(i=0;i<32;i++)
        printf("%d,",sig[i]);
    printf("\n");
    printf("check correctness\n");
    crypto_sign_open( msg, &mlen, sig, siglen, pk);


    free(pk);
    free(sk);
    free(sig);
    return 0;

}

int test_nist_api_KAT()
{

    int i;
    unsigned char       *sig;
    unsigned char       *pk, *sk;
    unsigned long long  siglen;
    unsigned long long  mlen;

    pk  = malloc(sizeof(unsigned char)* 5000);
    sk  = malloc(sizeof(unsigned char)* 10000);
    sig = malloc(sizeof(unsigned char)* 5000);

    if(!pk||!sk||!sig)
    {
        printf("malloc error!\n");
        return -1;
    }
    memset(pk, 0, sizeof(unsigned char)* 5000);
    memset(sk, 0, sizeof(unsigned char)* 10000);
    memset(sig,0, sizeof(unsigned char)* 5000);

    mlen = get_len(msg);





    /* generate a set of keys */
    printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");
    printf("testing NIST API with KAT string %s: \n", rndness);

    crypto_sign_keypair_KAT(pk, sk, rndness);


    printf("key generated, public key (first 32 bytes):\n");

    for(i=0;i<32;i++)
        printf("%d,",pk[i]);
    printf("\n");

    printf("and secret key (first 32 bytes):\n");
    for(i=0;i<32;i++)
        printf("%d,",sk[i]);
    printf("\n");

    printf("begin a single signing procedure\n");

    crypto_sign_KAT(sig, &siglen, msg, mlen, sk, rndness);


    printf("signature of length %d:\n", (int)siglen);
    for(i=0;i<32;i++)
        printf("%d,",sig[i]);
    printf("\n");

    printf("check correctness\n");
    crypto_sign_open(msg, &mlen, sig, siglen, pk);


    memset(pk, 0, sizeof(unsigned char)* 5000);
    memset(sk, 0, sizeof(unsigned char)* 10000);
    memset(sig,0, sizeof(unsigned char)* 5000);

    free(pk);
    free(sk);
    free(sig);
    return 0;

}



int main(void)
{
    //test_basic();
    //test_nist_api();
    //test_nist_api_KAT();
	
	//FIRST TRY TO AGGREGATE TWO SIGNATURES AND VERIFY REST IS EASY
	PQ_PARAM_SET_ID plist = Gaussian_512_107;
	PQ_PARAM_SET *param = pq_get_param_set_by_id(plist);
	int64_t   *f, *g, *g_inv, *h, *h_inv, *buf, *buf2, *sig, *mem, *v, *v2, *sig2, *sptp, *sptp2, *u, *Beta, *Gamma, *vAdd, *sptpAdd;

    int i =0;
	int j = 0;
	int ii = 1;
	int k = 32;
	uint16_t hash = 0;
	unsigned char randNum[16];
	unsigned char concat[48] = {0};
	unsigned char hashedM[32];
	unsigned char message[32] = {0};
	double timeSign, timeVer;
    timeSign = 0.0;
    timeVer = 0.0;
    clock_t start, start2;
	clock_t end, end2;
	
	
    unsigned char   *msg, *messages;
	unsigned char   *msg2;
    unsigned char   *seed   = (unsigned char*) "nist submission";
	unsigned char   *seed2   = (unsigned char*) "just a random message";
    size_t          msg_len = 64;

    /* memory to store keys/msgs/ctx */
    mem = malloc (sizeof(int64_t)*param->padded_N * 18);
    /* buffer */
    buf = malloc (sizeof(int64_t)*param->padded_N * 12);
	buf2 = malloc (sizeof(int64_t)*param->padded_N * 12);
	Beta = malloc (sizeof(int64_t)*param->padded_N * 256);
	Gamma = malloc (sizeof(int64_t)*param->padded_N * 8192);
	vAdd = malloc (sizeof(int64_t)*param->padded_N);
	sptpAdd = malloc (sizeof(int64_t)*param->padded_N*2);
	messages = malloc (sizeof(unsigned char)*64*8192);
    /* message to be signed */
    msg = malloc (sizeof(unsigned char)*msg_len);
	msg2 = malloc (sizeof(unsigned char)*msg_len);


    if (!mem || !buf || !msg)
    {
        printf("malloc error!\n");
        return -1;
    }

    crypto_hash_sha512(msg, seed, msg_len);
	crypto_hash_sha512(msg2, seed2, msg_len);

    memset(mem, 0, sizeof(int64_t)*param->padded_N * 18);
    memset(buf, 0, sizeof(int64_t)*param->padded_N * 12);
	memset(buf2, 0, sizeof(int64_t)*param->padded_N * 12);
	memset(Beta, 0, sizeof(int64_t)*param->padded_N * 256);
	memset(Gamma, 0, sizeof(int64_t)*param->padded_N * 8192);
	memset(vAdd, 0, sizeof(int64_t)*param->padded_N);
	memset(sptpAdd, 0, sizeof(int64_t)*param->padded_N*2);


    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;
    sig     = h		+ param->padded_N*2;
	h_inv   = sig	+ param->padded_N*2;
	v 		= h_inv	+ param->padded_N*2;
	v2 		= v	+ param->padded_N;
	sig2 	= v2	+ param->padded_N;
	sptp 	= sig2	+ param->padded_N*2;
	sptp2 	= sptp	+ param->padded_N*2;
	u 	= sptp2	+ param->padded_N*2;
	//= u	+ param->padded_N;
	
	printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");
    printf("Begin SCRA Signing and Verification with %s \n", param->name);

	
	memset(buf, 0, sizeof(int64_t)*param->padded_N * 12);
    keygenPQ(f,g,g_inv,h,h_inv,buf,param);


	FILE *B = fopen("B.txt", "wb+");
	FILE *A = fopen("A.txt", "wb+");
	
	FILE *X = fopen("X.txt", "wb+");
	FILE *target = fopen("target.txt", "wb+");





//Keygen SCRA
	for (i = 0; i < 8192; ++i) {
		blake2b(messages+i*64, &hash, NULL, 64, 2, 0);
		memset(buf, 0, sizeof(int64_t)*param->N * 12);
		if(signPQ(sig, Gamma+i*param->N, messages+i*64, msg_len,f,g,g_inv,h,buf,param) == -1)
			printf("FAILEDDD === %d\n", i);
		hash = hash +1;
		//printf("Gamma = %d\n", Gamma[i*param->N]);
		
		for (j = 0; j < param->N -1; ++j) {
			fprintf(X, "%lld, " ,(long long)Gamma[j+i*param->N]);
		}
		fprintf(X, "%lld \n", (long long)Gamma[(i+1)*param->N -1]);
		
//		fprintf(X, "%lld, " ,(long long)Gamma[i]);
	}
//	hash = 0;
//	for (i = 0; i < 256; ++i) {
//		blake2b(msg, &hash, z, 64, 1, 32);
//		memset(buf, 0, sizeof(int64_t)*param->N * 12);
//		signPQ(sig, Beta+i*param->N, msg, msg_len,f,g,g_inv,h,buf,param);
//		hash = hash +1;
//	}
	
	printf("=====KEYGEN IS DONE=====");
	
//SIGN SCRA
	for (ii = 0; ii < 8161; ++ii) {
		memset(vAdd, 0, sizeof(int64_t)*param->padded_N);
		memset(sptpAdd, 0, sizeof(int64_t)*param->padded_N*2);
		
		start = clock();
		
		for (i = 0; i < 16; ++i) {
			randNum[i] = rand()%256;
		}
		
		memcpy(concat, message, 32);
		memcpy(concat + 32, randNum, 16);
		
		blake2b(hashedM, concat, NULL, 32,48,0);
//		printf("hashedM ==== %d\n", hashedM[2]);
		
		for (unsigned j = 0; j <32; ++j){
			for (i = 0; i < param->N; ++i) {
				vAdd[i] = Gamma[i+param->N*(hashedM[j]+(j*256))] + vAdd[i];
			}
			//printf("vAdd = %d\n", vAdd[j]);
		}
		
		end = clock();
		timeSign = timeSign + (double)(end-start);
		
//VERIFY/ATTACK SCRA (USE PUBLIC DATA ONLY)
		start2 = clock();
		for (i = 0; i < param->N -1; ++i) {
			fprintf(B, "%lld," ,(long long)vAdd[i]);
		}
		fprintf(B, "%lld\n", (long long)vAdd[param->N -1]);
		
		
		memcpy(concat, message, 32);
		memcpy(concat + 32, &randNum, 16);
		blake2b(hashedM, concat, NULL, 32,48,0);
		
		for (i = 0; i < 32; ++i) {
			hash = hashedM[i]+(i*256);
//			printf("hashed = %d\n", hash);
			for (j = 0; j < 256; ++j) {
				//i*256+j
				if(i*256+j != 8191){
					if(hash == (i*256+j)){
						fprintf(A, "%d,", 1);//Aslinda bir ustundekileri kullaniyor olabiliriz
					}
					else{
						fprintf(A, "%d,", 0);
					}
				}
			}
		}
		if(hash == (8191)){
			fprintf(A, "%d\n", 1);
		}
		else{
			fprintf(A, "%d\n", 0);
		}
		
		end2 = clock();
		//printf("HASH ==== %d\n", hash);
//END ATTACK GO ON VERIFICATION


		memcpy(concat, message, 32);
		memcpy(concat + 32, randNum, 16);
		blake2b(hashedM, concat, NULL, 32,48,0);
		
		hash = hashedM[0];
		blake2b(msg, &hash, NULL, 64, 2, 0);
		challenge (sptpAdd, h, msg, msg_len, param);
		for (unsigned j = 1; j < 32; ++j) {
			hash = hashedM[j]+(j*256);
			blake2b(msg, &hash, NULL, 64, 2, 0);
			challenge (sptp2, h, msg, msg_len, param);
			for (i=0;i<param->N*2;i++){
				sptpAdd[i] = sptp2[i] + sptpAdd[i];
			}
		}
		
		
		
		/* u = v * h^-1 */
		memset(buf2, 0, sizeof(int64_t)*param->N * 12);
		pol_mul_coefficients(u, vAdd, h_inv, param, buf2);
		
		
		//CHECK MAX NORM HERE FIRST tau = 13.3, k = 2, sigma = 107, 
		
		if (max_norm(u, param->N)> param->p*13.3*k*107)
		{
			printf("Max Norm failed");
		}
		
		/* check if u,v \equiv u_p,v_p mod p */
		for (i=0;i<param->N;i++)
		{
			if ((vAdd[i]-sptpAdd[i+param->N]) % param->p != 0 || (u[i]-sptpAdd[i]) % param->p !=0)
			{
				printf("congruent condition failed for param %s \nv:\n", param->name);

				//printf("sig:\n");
				//for (i=0;i<param->padded_N;i++)
				   // printf("%lld,", (long long) sig[i]);
				printf("\nu:\n");
				for (i=0;i<param->padded_N;i++)
					printf("%lld,", (long long) u[i]%param->p);
				printf("\nv:\n");
				for (i=0;i<param->padded_N;i++)
					printf("%lld,", (long long) v[i]%param->p);
				printf("\nsptpUpart:\n");
				for (i=0;i<param->padded_N;i++)
					printf("%lld,", (long long) sptp[i]%param->p);
				printf("\nsptpVpart:\n");
				for (i=0;i<param->padded_N;i++)
					printf("%lld,", (long long) sptp[i+param->N]%param->p);
				printf("\nmsg:\n");
				for (i=0;i<param->padded_N;i++)
					printf("%lld, ", (long long) msg[i+param->N]);
				printf("\n\n");

				//return -1;
			}
			else{
				//printf("Aggregation Successful!");
			}
		}
		

		timeVer = timeVer + (double)(end2-start2);
		
	}
	
	
	
	//FIND INDEXES ON TARGET MESSAGE
	unsigned char message2[22] = {"FIRE THE ROCKETS, NOW!"};
	memcpy(concat, message2, 22);
	memcpy(concat + 22, &randNum, 16);
	blake2b(hashedM, concat, NULL, 32,38,0);
	
	for (i = 0; i < 32; ++i) {
		hash = hashedM[i]+(i*256);
//			printf("hashed = %d\n", hash);
		for (j = 0; j < 256; ++j) {
			//i*256+j
			if(i*256+j != 8191){
				if(hash == (i*256+j)){
					fprintf(target, "%d,", 1);//Aslinda bir ustundekileri kullaniyor olabiliriz
				}
				else{
					fprintf(target, "%d,", 0);
				}
			}
		}
	}
	if(hash == (8191)){
		fprintf(target, "%d\n", 1);
	}
	else{
		fprintf(target, "%d\n", 0);
	}
	
	
	
	printf("%fus per sign\n", ((double) (timeSign * 1000)) / CLOCKS_PER_SEC / ii * 1000);
	printf("%fus per verification\n", ((double) (timeVer * 1000)) / CLOCKS_PER_SEC / ii * 1000);
	printf("%fus end-to-end delay\n", ((double) ((timeSign+timeVer) * 1000)) / CLOCKS_PER_SEC / ii * 1000);
	
	fclose(B);
	fclose(A);
	fclose(X);
	fclose(target);
	
	
	

    /* generate a set of keys */
    printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");
    printf("testing parameter set %s \n", param->name);


    printf("begin a single signing procedure\n");




    
	
//	printf("\n h_inv:\n");
//	for (i=0;i<param->padded_N;i++)
//		printf("%lld,", (long long) h_inv[i]%param->p);

	printf("now signing a message\n");
	memset(buf, 0, sizeof(int64_t)*param->N * 12);
    signPQ(sig, v, msg, msg_len,f,g,g_inv,h,buf,param);
	memset(buf, 0, sizeof(int64_t)*param->N * 12);
	signPQ(sig2, v2, msg2, msg_len, f,g,g_inv,h,buf,param);
	
	challenge (sptp, h, msg, msg_len, param);
	challenge (sptp2, h, msg2, msg_len, param);
	
	for (i=0;i<param->N;i++)
		v[i] = v2[i] + v[i];
		
	for (i=0;i<param->N*2;i++)
		sptp[i] = sptp2[i] + sptp[i];
		
	/* u = v * h^-1 */
	memset(buf, 0, sizeof(int64_t)*param->N * 12);
	pol_mul_coefficients(u, v, h_inv, param, buf2);
	
	
	//CHECK MAX NORM HERE FIRST tau = 13.3, k = 2, sigma = 107, 
	
	if (max_norm(u, param->N)> param->p*13.3*k*107)
	{
		printf("Max Norm failed");
	}
	
	/* check if u,v \equiv u_p,v_p mod p */
    for (i=0;i<param->N;i++)
    {
        if ((v[i]-sptp[i+param->N]) % param->p != 0 || (u[i]-sptp[i]) % param->p !=0)
        {
            printf("congruent condition failed for param %s \nv:\n", param->name);

            //printf("sig:\n");
            //for (i=0;i<param->padded_N;i++)
               // printf("%lld,", (long long) sig[i]);
            printf("\nu:\n");
            for (i=0;i<param->padded_N;i++)
                printf("%lld,", (long long) u[i]%param->p);
            printf("\nv:\n");
            for (i=0;i<param->padded_N;i++)
                printf("%lld,", (long long) v[i]%param->p);
            printf("\nsptpUpart:\n");
            for (i=0;i<param->padded_N;i++)
                printf("%lld,", (long long) sptp[i]%param->p);
			printf("\nsptpVpart:\n");
            for (i=0;i<param->padded_N;i++)
                printf("%lld,", (long long) sptp[i+param->N]%param->p);
            printf("\nmsg:\n");
            for (i=0;i<param->padded_N;i++)
                printf("%lld, ", (long long) msg[i+param->N]);
            printf("\n\n");

            //return -1;
        }
		else{
			//printf("Aggregation Successful!");
		}
    }
	
	
	
//	memset(buf, 0, sizeof(int64_t)*param->N * 12);
//	printf("=====================================\n");
//
//    printf("now verifying the signature: 0 for valid, -1 for invalid:   ");
//    /* verifying the signature */
//    memset(buf, 0, sizeof(int64_t)*param->N * 12);
//    printf("%d \n", verify(sig, msg, msg_len, h,buf,param));
//    printf("=====================================\n");
//	
//	
//	printf("now verifying the signature: 0 for valid, -1 for invalid:   ");
//    /* verifying the signature */
//    memset(buf, 0, sizeof(int64_t)*param->N * 12);
//    printf("%d \n", verify(sig2, msg2, msg_len, h,buf,param));
    printf("=====================================\n");

    printf("\n\n!!!Hello onboard security!!!\n");
	
	free(mem);
    free(buf);
	free(buf2);
	free(msg);
	free(msg2);
    exit(EXIT_SUCCESS);
}
