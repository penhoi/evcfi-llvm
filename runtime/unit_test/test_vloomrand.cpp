#include <CppUTest/TestHarness.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vloom_func.h"

TEST_GROUP(test_vloomrand){

};

TEST(test_vloomrand, randint)
{
    uint64_t d64 = vloom_rand_int64();
    uint32_t d32 = vloom_rand_int32();

    CHECK(d64 != 0);
    CHECK(d32 != 0);

    CHECK((uint32_t)d64 != d32);
}

TEST(test_vloomrand, randbuf)
{

    char szBuf64[64 + 8] = {0};
    char szBuf32[32 + 8] = {0};

    CHECK(szBuf64[0] == 0);
    CHECK(szBuf32[0] == 0);

    vloom_rand_buffer(szBuf64, 64);
    vloom_rand_buffer(szBuf32, 32);

    CHECK(szBuf64[0] != 0);
    CHECK(szBuf32[0] != 0);

    CHECK(strncmp(szBuf64, szBuf32, 32) != 0);
}

#include <CppUTest/CommandLineTestRunner.h>

int main(int ac, char **av)
{
    return CommandLineTestRunner::RunAllTests(ac, av);
}