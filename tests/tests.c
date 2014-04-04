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
#include <string.h>

#include "sha3.h"

typedef enum
{
    SHA3_TEST_PASSED = 0,
    SHA3_TEST_FAILS,
    SHA3_TEST_NOT_IMPLEMENTED
}sha3_test_result_t;

//---------------------------------------------------------------------
static void print_test_info(uint32_t test_num, sha3_test_result_t res)
{
    printf("\n ************************************************* \n");
    //TODO
}

//---------------------------------------------------------------------
static void print_test_result(uint32_t test_num, sha3_test_result_t res)
{
    printf("\n ************************************************* \n");
    if (SHA3_TEST_PASSED == res)
    {
        printf("\n *************  SHA3 TEST %d PASSED  ************* \n", test_num);
    }
    else if (SHA3_TEST_FAILS == res)
    {
        printf("\n *************  SHA3 TEST %d FAILED  ************* \n", test_num);
    }
    else
    {
        printf("\n ********  SHA3 TEST %d NOT_IMPLEMENTED  ********* \n", test_num);
    }
    printf("\n ************************************************** \n");
}

//-------------------------------------------------------------------
//   TESTS
//--------------------------------------------------------------------

static sha3_test_result_t sha3_null_string_test(sha3_hash_modes_t sha3_mode, uint32_t repeat_num)
{
    sha3_test_result_t test_res = SHA3_TEST_FAILS;

    const uint8_t input_str[] = "";

    uint8_t output_str[SHA3_512_HASH_LEN] = {0};

    //TODO add test vectors
    const uint8_t output_reference_res_sha3_224[SHA3_224_HASH_LEN] = {0};
    const uint8_t output_reference_res_sha3_256[SHA3_256_HASH_LEN] = {0};
    const uint8_t output_reference_res_sha3_384[SHA3_384_HASH_LEN] = {0};
    const uint8_t output_reference_res_sha3_512[SHA3_512_HASH_LEN] = {0};

    sha3_status_t res  = SHA3_ERROR;

    int i = 0;

    for(i = 0; i < repeat_num; i++)
    {
        res = SHA3(sha3_mode, input_str, (uint32_t)strlen((const char *)input_str), output_str);

        if(SHA3_ERROR == res)
        {
            return SHA3_TEST_FAILS;
        }

        switch (sha3_mode)
        {
            case SHA3_224:
                if(!memcmp(output_reference_res_sha3_224, output_str, SHA3_224_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            case SHA3_256:
                if(!memcmp(output_reference_res_sha3_256, output_str, SHA3_256_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            case SHA3_384:
                if(!memcmp(output_reference_res_sha3_384, output_str, SHA3_384_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            case SHA3_512:
                if(!memcmp(output_reference_res_sha3_512, output_str, SHA3_512_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            default:
                test_res = SHA3_TEST_FAILS;
                break;

        }

        if(SHA3_TEST_FAILS == test_res)
        {
            print_test_result(i, test_res);
            return test_res;
        }
    }

    print_test_result(i, test_res);
    return test_res;
}

//---------------------------------------------------------------------
static sha3_test_result_t sha3_ancronim_string_test(sha3_hash_modes_t sha3_mode, uint32_t repeat_num)
{
    sha3_test_result_t test_res = SHA3_TEST_FAILS;

    const uint8_t input_str[] = "The quick brown fox jumps over the lazy dog";

    uint8_t output_str[SHA3_512_HASH_LEN] = {0};

    //TODO add test vectors
    const uint8_t output_reference_res_sha3_224[SHA3_224_HASH_LEN] = {0};
    const uint8_t output_reference_res_sha3_256[SHA3_256_HASH_LEN] = {0};
    const uint8_t output_reference_res_sha3_384[SHA3_384_HASH_LEN] = {0};
    const uint8_t output_reference_res_sha3_512[SHA3_512_HASH_LEN] = {0};

    sha3_status_t res  = SHA3_ERROR;

    int i = 0;

    for(i = 0; i < repeat_num; i++)
    {
        res = SHA3(sha3_mode, input_str, (uint32_t)strlen((const char *)input_str), output_str);

        if(SHA3_ERROR == res)
        {
            return SHA3_TEST_FAILS;
        }

        switch (sha3_mode)
        {
            case SHA3_224:
                if(!memcmp(output_reference_res_sha3_224, output_str, SHA3_224_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            case SHA3_256:
                if(!memcmp(output_reference_res_sha3_256, output_str, SHA3_256_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            case SHA3_384:
                if(!memcmp(output_reference_res_sha3_384, output_str, SHA3_384_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            case SHA3_512:
                if(!memcmp(output_reference_res_sha3_512, output_str, SHA3_512_HASH_LEN))
                {
                    test_res = SHA3_TEST_PASSED;
                }
                else
                {
                    test_res = SHA3_TEST_FAILS;
                }
                break;
            default:
                test_res = SHA3_TEST_FAILS;
                break;

        }

        if(SHA3_TEST_FAILS == test_res)
        {
            print_test_result(i, test_res);
            return test_res;
        }
    }

    print_test_result(i, test_res);
    return test_res;
}

//---------------------------------------------------------------------
static sha3_test_result_t sha3_sream_test(sha3_hash_modes_t sha3_mode)
{
    //TODO
    return SHA3_TEST_NOT_IMPLEMENTED;
}

//---------------------------------------------------------------------
int main(void)
{
    sha3_null_string_test(SHA3_256, 1);
    sha3_ancronim_string_test(SHA3_256, 1);
	
    return 0;
}
