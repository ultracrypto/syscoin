/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <secp256k1.h>
#include <iostream>
#include <iomanip>
#include <sys/time.h>
#include "../src/secp256k1/src/util.h"
#include "thread_pool/thread_pool.hpp"
static double gettimedouble(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_usec * 0.000001 + tv.tv_sec;
}
tp::ThreadPool *threadpool = NULL;
void print_number(double x) {
	double y = x;
	int c = 0;
	if (y < 0.0) {
		y = -y;
	}
	while (y > 0 && y < 100.0) {
		y *= 10.0;
		c++;
	}
	printf("%.*f", c, x);
}

void run_benchmark(char *name, void(*benchmark)(void*), void(*setup)(void*), void(*teardown)(void*), void* data, int count, int iter) {
	int i;
	double min = HUGE_VAL;
	double sum = 0.0;
	double max = 0.0;

	for (i = 0; i < count; i++) {
		double begin, total;
		if (setup != NULL) {
			setup(data);
		}
		begin = gettimedouble();
		benchmark(data);
		total = gettimedouble() - begin;
		if (teardown != NULL) {
			teardown(data);
		}
		if (total < min) {
			min = total;
		}
		if (total > max) {
			max = total;
		}
		sum += total;
	}
	printf("%s: min ", name);
	print_number(min * 1000000.0 / iter);
	printf("us / avg ");
	print_number((sum / count) * 1000000.0 / iter);
	printf("us / max ");
	print_number(max * 1000000.0 / iter);
	printf("us\n");
}

typedef struct {
    secp256k1_context *ctx;
    unsigned char msg[32];
    unsigned char key[32];
    unsigned char sig[72];
    size_t siglen;
    unsigned char pubkey[33];
    size_t pubkeylen;
} benchmark_verify_t;

static void benchmark_verify(void* arg) {
    int i;
    benchmark_verify_t* data = (benchmark_verify_t*)arg;

    for (i = 0; i < 20000; i++) {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pubkey, data->pubkey, data->pubkeylen) == 1);
        CHECK(secp256k1_ecdsa_signature_parse_der(data->ctx, &sig, data->sig, data->siglen) == 1);
        CHECK(secp256k1_ecdsa_verify(data->ctx, &sig, data->msg, &pubkey) == (i == 0));
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
    }
}
static void benchmark_verify_parallel(void* arg) {
    int i;
    benchmark_verify_t* data = (benchmark_verify_t*)arg;

    for (i = 0; i < 20000; i++) {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pubkey, data->pubkey, data->pubkeylen) == 1);
        CHECK(secp256k1_ecdsa_signature_parse_der(data->ctx, &sig, data->sig, data->siglen) == 1);
        CHECK(secp256k1_ecdsa_verify(data->ctx, &sig, data->msg, &pubkey) == (i == 0));
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
    }
}
int main(int argc, char* argv[])
{
    int i;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    benchmark_verify_t data;
	threadpool = new tp::ThreadPool;
    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    for (i = 0; i < 32; i++) {
        data.msg[i] = 1 + i;
    }
    for (i = 0; i < 32; i++) {
        data.key[i] = 33 + i;
    }
    data.siglen = 72;
    CHECK(secp256k1_ecdsa_sign(data.ctx, &sig, data.msg, data.key, NULL, NULL));
    CHECK(secp256k1_ecdsa_signature_serialize_der(data.ctx, data.sig, &data.siglen, &sig));
    CHECK(secp256k1_ec_pubkey_create(data.ctx, &pubkey, data.key));
    data.pubkeylen = 33;
    CHECK(secp256k1_ec_pubkey_serialize(data.ctx, data.pubkey, &data.pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

    run_benchmark("ecdsa_verify", benchmark_verify, NULL, NULL, &data, 10, 20000);
	run_benchmark("ecdsa_verify_parallel", benchmark_verify_parallel, NULL, NULL, &data, 10, 20000);
	delete threadpool;
    secp256k1_context_destroy(data.ctx);
    return 0;
}
