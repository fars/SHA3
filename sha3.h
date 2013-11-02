/**
* @file  sha.h
* @brief SHA3 module main interface. Contain definitions SHA3
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


typedef enum Sha3HashLen
{
	SHA3_512 = 0,
	SHA3_384,
	SHA3_256,
	SHA3_224
} Sha3HashLen_t;

typedef enum Sha3CalcStatus
{
	SHA3_CALC_OK = 0,
	SHA3_CALC_ERROR
}Sha3CalcStatus_t;


#endif // __SHA3_H_
