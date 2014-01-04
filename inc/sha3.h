/**
* @file  sha.h
* @brief SHA3 module main interface.
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

#ifndef __SHA3_H_
#define __SHA3_H_

#ifdef  __cplusplus
extern "C" {
#endif

/** SHA3 hash length for modes (in bytes) */
#define SHA3_224_HASH_LEN (224/8)
#define SHA3_256_HASH_LEN (256/8)
#define SHA3_384_HASH_LEN (384/8)
#define SHA3_512_HASH_LEN (512/8)

/**
 * SHA3 (Keccak) modes.
 */
typedef enum sha3_hash_modes
{
	SHA3_224 = 0,
	SHA3_256,
	SHA3_384,
	SHA3_512
} sha3_hash_modes_t;

/**
 * Result definition.
 */
typedef enum
{
	SHA3_OK = 0,
	SHA3_ERROR
}sha3_status_t;

/**
 * SHA3 (Keccak) context.
 */
typedef struct sha3_ctx{
        uint8_t a[200];
        uint16_t r;
        uint16_t c;
        uint16_t d;
        uint8_t  bs;
} sha3_ctx_t;

/**
 * @brief          SHA3 context setup
 *
 * @param mode     [in] SHA3 hash mode
 * @param ctx      [in] pointer to context to be initialized
 *
 * @return         status of operation
 */
sha3_status_t sha3_init(sha3_hash_modes_t mode, sha3_ctx_t *ctx); 

/**
 * @brief             SHA3 input data chunks processing
 *
 * @param ctx         [in] SHA3 context
 * @param input_data  [in] pointer to buffer with plain data chunck
 * @param len         [in] plain data chunk len in bytes
 *
 * @return            status of operation
 */

sha3_status_t sha3_update(sha3_ctx_t *ctx, const uint8_t *input_data, uint32_t len);

/**
 * @brief             Returns SHA3 hash
 *
 * @param ctx         [in] SHA3 context
 * @param output_data [out] pointer to buffer with hash
 *
 * @return            status of operation
 */
sha3_status_t sha3_final(sha3_ctx_t *ctx, uint8_t *output_data);

/**
 * @brief             HSHA3 single data chunk processing
 *
 * @param mode        [in] SHA3 hash mode
 * @param input_data  [in] pointer to buffer with plain data chunck
 * @param len         [in] plain data chunk len in bytes
 * @param output_data [out] pointer to buffer with hash
 *
 * @return            status of operation
 */
sha3_status_t SHA3(sha3_hash_modes_t mode,
                   const uint8_t *input_data,
                   uint32_t len,
                   uint8_t *output_data);

#ifdef  __cplusplus
}
#endif

#endif // __SHA3_H_
