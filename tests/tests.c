/*
 ============================================================================
 Name        : test.c
 Author      : Sergii Sidorov
 Version     : 1.0.0
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */
#include <stdio.h>
#include <stdint.h>

#include "sha3.h"

int main(void) 
{
	sha3_ctx_t ctx;
	sha3_init(SHA3_256 ,&ctx);
	
	
	return EXIT_SUCCESS;
}
