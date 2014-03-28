/**
* @file  hmac_sha3.c
* @brief HMAC-SHA3 module implementation
* @author Sergii Sidorov(sergii.sidorov@ukr.net)
*
* @date  03.01.2014
*
* The MIT License (MIT)
*
* Copyright (c) 2014 Sergii Sidorov
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

#include <string.h>

#include "hmac_sha3.h"



//-----------------------------------------------------------------------------
hmac_sha3_status_t hmac_sha3_init(hmac_sha3_hash_mode_t mode,
                                  hmac_sha3_ctx_t *ctx,
                                  const uint8_t *key,
                                  int key_len)
{
    int i;

    if ( (NULL == ctx) || (NULL == key) )
    {
        return HMAC_SHA3_ERROR;
    }

    memset (ctx, 0, sizeof(hmac_sha3_ctx_t) );

    switch(mode)
    {
        case HMAC_SHA3_224:
            ctx->sha_mode = SHA3_224;
            ctx->blocksize = SHA3_224_HMAC_LEN;
            break;
        case HMAC_SHA3_256:
            ctx->sha_mode = SHA3_256;
            ctx->blocksize = SHA3_256_HMAC_LEN;
            break;
        case HMAC_SHA3_384:
            ctx->sha_mode = SHA3_384;
            ctx->blocksize = SHA3_384_HMAC_LEN;
            break;
        case HMAC_SHA3_512:
            ctx->sha_mode = SHA3_512;
            ctx->blocksize = SHA3_512_HMAC_LEN;
            break;
        default:
            return HMAC_SHA3_ERROR;
    }

     // Step 1. If key is longer than blocksize  reset it to key = HASH(key)
    if (key_len > ctx->blocksize)
    {
        SHA3(ctx->sha_mode, key, key_len, (uint8_t*)key);
        key_len = ctx->blocksize;
    }

    // Step 2. Start out by storing key in pads
    memset(ctx->ipad, 0, HMAC_MAX_KEY_LEN);
    memset(ctx->opad, 0, HMAC_MAX_KEY_LEN);

    memcpy( ctx->ipad, key, key_len);
    memcpy( ctx->opad, key, key_len);

    // Step 3. XOR key with ipad and opad values
    for (i = 0; i < HMAC_MAX_KEY_LEN; i++)
    {
        ctx->ipad[i] ^= IPAD;
        ctx->opad[i] ^= OPAD;
    }

    sha3_init(ctx->sha_mode, &ctx->ctx);
    sha3_update(&ctx->ctx, ctx->ipad, HMAC_MAX_KEY_LEN);

    return HMAC_SHA3_OK;
}


//-----------------------------------------------------------------------------
hmac_sha3_status_t hmac_sha3_update(hmac_sha3_ctx_t *ctx,
                                    const uint8_t *input_data,
                                    uint32_t len)
{
    if ( (NULL == ctx) || (NULL == input_data) )
    {
        return HMAC_SHA3_ERROR;
    }

    if ( SHA3_OK == sha3_update(&ctx->ctx, input_data, len) )
    {
        return HMAC_SHA3_OK;
    }

    return HMAC_SHA3_ERROR;
}


//-----------------------------------------------------------------------------
hmac_sha3_status_t hmac_sha3_final(hmac_sha3_ctx_t *ctx, uint8_t *output_data)
{

    sha3_ctx_t out_ctx;
    sha3_status_t res = SHA3_ERROR;

    if ( (NULL == ctx) || (NULL == output_data) )
    {
        return HMAC_SHA3_ERROR;
    }

    if ( SHA3_OK != sha3_final(&ctx->ctx, output_data) )
    {
        return HMAC_SHA3_ERROR;
    }

    res = sha3_init(ctx->sha_mode , &out_ctx);
    res = sha3_update(&out_ctx, ctx->opad, ctx->blocksize);
    res = sha3_final(&out_ctx, output_data);

    if(SHA3_OK != res)
    {
        return HMAC_SHA3_ERROR;
    }

    return HMAC_SHA3_OK;
}


//-----------------------------------------------------------------------------
hmac_sha3_status_t HMAC_SHA3(hmac_sha3_hash_mode_t mode,
                             const uint8_t *input_data,
                             uint32_t len,
                             const uint8_t *key,
                             int key_len,
                             uint8_t *output_data)
{
    hmac_sha3_status_t res = HMAC_SHA3_OK;
    hmac_sha3_ctx_t ctx;

    if ( (input_data == NULL) || (output_data == NULL) || (key == NULL) )
    {
        return HMAC_SHA3_ERROR;
    }

    res = hmac_sha3_init(mode , &ctx, key, key_len);
    res = hmac_sha3_update(&ctx, input_data, len);
    res = hmac_sha3_final(&ctx, output_data);

    return res;
}
