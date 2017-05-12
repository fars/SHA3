/**
* @file  sha.c
* @brief SHA3 module implementation
* @author Sergii Sidorov(sergii.sidorov@ukr.net)
*
* @date  02.11.2013
*
* The MIT License (MIT)
*
* Copyright (c) 2013 Sergii Sidorov
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of
* this software and associated documentation files (the "Software"), to deal in
* the Software without restriction, including without limitation the rights to
* use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
* the Software, and to permit persons to whom the Software is furnished to do so,
* subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
* COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
* IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "sha3.h"

// TODO: define all magic here
#define KECCAK_VECTOR_LEN 5

// pseudo random round constants
static const uint64_t RC[24]={
               0x0000000000000001,
		       0x0000000000008082,
		       0x800000000000808A,
		       0x8000000080008000,
		       0x000000000000808B,
		       0x0000000080000001,
		       0x8000000080008081,
		       0x8000000000008009,
		       0x000000000000008A,
		       0x0000000000000088,
		       0x0000000080008009,
		       0x000000008000000A,
		       0x000000008000808B,
		       0x800000000000008B,
		       0x8000000000008089,
		       0x8000000000008003,
		       0x8000000000008002,
		       0x8000000000000080,
		       0x000000000000800A,
		       0x800000008000000A,
		       0x8000000080008081,
		       0x8000000000008080,
		       0x0000000080000001,
		       0x8000000080008008
};


//rotation offsets
static const uint64_t keccakf_rotc[24] =
{
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44,
};

static const uint64_t keccakf_piln[24] =
{
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1,
};


#define ROTL64(x, y)        (((x) << (y)) | ((x) >> (64 - (y))))

// Keccak round function
//------------------------------------------------
static void keccak_fn(uint64_t s[25], uint32_t rounds)
{
    register int i, j, round;
    register uint64_t t;
    uint64_t bc[5];

    for(round = 0; round < rounds; round++)
    {
            //Theta step
            for(i = 0; i < 5; i++)
            {
                bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
            }

            for(i = 0; i < 5; i++)
            {
                t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for(j = 0; j < 25; j += 5)
                {
                        s[j + i] ^= t;
                }
            }

            //Rho and Pi steps
            t = s[1];
            for(i = 0; i < 24; i++)
            {
                j = keccakf_piln[i];
                bc[0] = s[j];
                s[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            //Chi step
            for(j = 0; j < 25; j += 5)
            {
                for(i = 0; i < 5; i++)
                {
                    bc[i] = s[j + i];
                }

                for(i = 0; i < 5; i++)
                {
                    s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            //Iota step
            s[0] ^= RC[round];
    }
}

//-------------------------------------------------------
static sha3_status_t sha3_sponge_absorb(sha3_ctx_t *ctx, const uint8_t * input_data, uint32_t len)
{
    //TODO
    return SHA3_OK;
}

//-------------------------------------------------------
static sha3_status_t sha3_sponge_squeeze(sha3_ctx_t *ctx, uint8_t *output_data)
{
    //TODO
    return SHA3_OK;
}

//-------------------------------------------------------
sha3_status_t sha3_init(sha3_hash_modes_t mode, sha3_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(sha3_ctx_t) );
    
    switch(mode)
    {
    	case SHA3_224: 
    		ctx->r = 1152; 
    		ctx->c = 448; 
    		ctx->d = 28;
    		break;
    	case SHA3_256: 
    		ctx->r = 1088; 
    		ctx->c = 512; 
    		ctx->d = 32;
    		break;
    	case SHA3_384:
    		ctx->r = 832; 
    		ctx->c = 768; 
    		ctx->d = 48;
    		break;
    	case SHA3_512: 
    		ctx->r = 576; 
    		ctx->c = 1024; 
    		ctx->d = 64;
    		break;
    	default:
    		return SHA3_ERROR;
    }
    
    ctx->bs = (uint8_t)(ctx->r / 8);
        
    return SHA3_OK;
}

//-------------------------------------------------------
sha3_status_t sha3_update(sha3_ctx_t *ctx, const uint8_t * input_data, uint32_t len)
{
    return sha3_sponge_absorb(ctx, input_data, len);
}

//-------------------------------------------------------
sha3_status_t sha3_final(sha3_ctx_t *ctx, uint8_t * output_data)
{
    return sha3_sponge_squeeze(ctx, output_data);
}

//-------------------------------------------------------
sha3_status_t SHA3(sha3_hash_modes_t mode, const uint8_t *input_data, uint32_t len, uint8_t *output_data)
{
	sha3_status_t res = SHA3_OK; 
	sha3_ctx_t ctx;
	
	if ( (input_data == NULL) || (output_data == NULL) )
	{
		return SHA3_ERROR;
	}
	
	res = sha3_init(mode ,&ctx);
	res = sha3_update(&ctx, input_data, len);
	res = sha3_final(&ctx, output_data);
	
	return res;
}
