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
#include <stdlib.h>


#include "sha3.h"

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
static const uint64_t r[KECCAK_VECTOR_LEN][KECCAK_VECTOR_LEN]={ 
							{0,36,3,41,18},
							{1,44,10,45,2},
							{62,6,43,15,61},
							{28,55,25,21,56},
							{27,20,39,8,14}
						   };


//-------------------------------------------------
static inline int mod (int a, int b)
{
  if(b < 0)
  {
    return mod(-a, -b);
  }

  int ret = a % b;

  if(ret < 0)
  {
    ret+=b;
  }

  return ret;
}

// Keccak round
//------------------------------------------------
static void keccak(uint64_t (*A)[KECCAK_VECTOR_LEN])
{
  int i;
  uint64_t C[KECCAK_VECTOR_LEN];
  uint64_t D[KECCAK_VECTOR_LEN];
  uint64_t B[KECCAK_VECTOR_LEN][KECCAK_VECTOR_LEN];
  uint8_t x, y;

  for(i = 0; i < 24; i++)
  { 
	// Theta step 
    for(x = 0;x < KECCAK_VECTOR_LEN; x++)
    {
      C[x] = A[x][0] ^ A[x][1] ^ A[x][2]^ A[x][3] ^ A[x][4];
    }

    for(x = 0;x < KECCAK_VECTOR_LEN; x++)
    {
      D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63));
    }
    
    for(x = 0; x < KECCAK_VECTOR_LEN; x++)
    {
      for(y = 0; y < KECCAK_VECTOR_LEN; y++)
      {
        A[x][y]=A[x][y]^D[x];
      }
    }

    //Rho and pi steps
    for(x = 0; x < KECCAK_VECTOR_LEN; x++)
    {
      for(y = 0;y < KECCAK_VECTOR_LEN; y++)
      {
        B[y][mod((2*x+3*y),5)]=((A[x][y] << r[x][y]) | (A[x][y] >> (64-r[x][y])));
      }
    }

    //Xi state
    for(x=0; x<KECCAK_VECTOR_LEN; x++)
    {
      for(y=0; y<KECCAK_VECTOR_LEN; y++)
      {
        A[x][y]=B[x][y]^((~B[mod((x+1),5)][y]) & B[mod((x+2),5)][y]);
      }
    }

    A[0][0]=A[0][0]^RC[i];
  }
  
}

