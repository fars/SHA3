/**
* @file  hmac_sha.h
* @brief HMAC-SHA3 module main interface
* @author Sergii Sidorov(sergii.sidorov@ukr.net)
*
* @date  04.01.2014
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

#ifndef __HMAC_SHA3_H_
#define __HMAC_SHA3_H_

#include <stdint.h>

#include "sha3.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * HMAC-SHA3 definitions.
 */

/** HMAC_SHA3 length for modes (in bytes) */
#define SHA3_224_HMAC_LEN (224/8)
#define SHA3_256_HMAC_LEN (256/8)
#define SHA3_384_HMAC_LEN (384/8)
#define SHA3_512_HMAC_LEN (512/8)

#define HMAC_MAX_KEY_LEN  64

#define IPAD 0x36
#define OPAD 0x5C

typedef enum 
{
	HMAC_SHA3_512 = 0,
	HMAC_SHA3_384,
	HMAC_SHA3_256,
	HMAC_SHA3_224
} hmac_sha3_hash_mode_t;

typedef enum 
{
	HMAC_SHA3_OK = 0,
	HMAC_SHA3_ERROR
}hmac_sha3_status_t;

/**
 * HMAC-SHA3 context.
 */
typedef struct hmac_sha3_ctx
{
    uint8_t           ipad[HMAC_MAX_KEY_LEN];                  // inner padding
    uint8_t           opad[HMAC_MAX_KEY_LEN];                  // outer padding
    sha3_hash_modes_t sha_mode;
    uint32_t          blocksize;
    sha3_ctx_t        ctx;
} hmac_sha3_ctx_t;


/**
 * @brief          HMAC-SHA3 context setup
 *
 * @param mode     [in] SHA3 hash mode
 * @param ctx      [in] pointer to context to be initialized
 * @param key      [in] pointer to key buffer
 * @param key_len  [in] key buffer len in bytes
 *
 * @return         status of operation
 */
hmac_sha3_status_t hmac_sha3_init(hmac_sha3_hash_mode_t mode,
                                  hmac_sha3_ctx_t *ctx,
                                  const uint8_t *key,
                                  int key_len);

/**
 * @brief             HMAC-SHA3 input data chunks processing
 *
 * @param ctx         [in] HMAC-SHA3 context
 * @param input_data  [in] pointer to buffer with plain data chunck
 * @param len         [in] plain data chunk len in bytes
 *
 * @return            status of operation
 */
hmac_sha3_status_t hmac_sha3_update(hmac_sha3_ctx_t *ctx,
                                    const uint8_t *input_data,
                                    uint32_t len);

/**
 * @brief             Returns HMAC-SHA3 cipher text
 *
 * @param ctx         [in] HMAC-SHA3 context
 * @param output_data [out] pointer to buffer with cipher text
 *
 * @return            status of operation
 */
hmac_sha3_status_t hmac_sha3_final(hmac_sha3_ctx_t *ctx, uint8_t *output_data);


/**
 * @brief             HMAC-SHA3 single data chunk processing
 *
 * @param mode        [in] HMAC-SHA3 hash mode
 * @param input_data  [in] pointer to buffer with plain data chunck
 * @param len         [in] plain data chunk len in bytes
 * @param key         [in] pointer to key buffer
 * @param key_len     [in] key buffer len in bytes
 * @param output_data [out] pointer to buffer with cipher text
 *
 * @return            status of operation
 */
hmac_sha3_status_t HMAC_SHA3(hmac_sha3_hash_mode_t mode,
                             const uint8_t *input_data,
                             uint32_t len,
                             const uint8_t *key,
                             int key_len,
                             uint8_t *output_data);



#ifdef  __cplusplus
}
#endif


#endif // __HMAC_SHA3_H_
