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


#ifdef  __cplusplus
extern "C" {
#endif

/** HMAC_SHA3 hash length for modes (in bytes) */
#define SHA3_224_HMAC_LEN (224/8)
#define SHA3_256_HMAC_LEN (256/8)
#define SHA3_384_HMAC_LEN (384/8)
#define SHA3_512_HMAC_LEN (512/8)


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


#ifdef  __cplusplus
}
#endif


#endif // __HMAC_SHA3_H_
