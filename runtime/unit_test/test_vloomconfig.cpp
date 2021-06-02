
#include <CppUTest/TestHarness.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <fcntl.h>
#include <unistd.h>

#include "../vloom.h"

/****************************************************************************/
/* VLOOM configuration                                                       */
/****************************************************************************/
bool vloom_config_readenv(VLOOM_EXECV_ENV *env, const char *szFName);

char **vloom_config_read_rtenvlist(const char *szFName);

VLOOM_FFIDERV_INFO *vloom_config_read_ffidervlist(const char *szFName);

TEST_GROUP(test_vloomconfig){

};

TEST(test_vloomconfig, readenv)
{
    /* generate configuration file */
    const char *szConf = "VLOOM_K:2\n"
                         "VLOOM_HASH:vloom_hash_add32\n"
                         "VLOOM_BLOOM32:true\n"
                         "VLOOM_FORCE_BLANK:true\n"
                         "VLOOM_FORCE_32:true\n"
                         "VLOOM_FORCE_COMPRESS:true\n"
                         "VLOOM_TRUNCATE:20\n"
                         "VLOOM_LOGFILE:log.txt\n"
                         "VLOOM_LOGLEVEL:4\n"
                         "VLOOM_RTENV_WHLIST:rtenvfile.txt\n"
                         "VLOOM_FFIDRV_WHLIST:ffidvfile.txt\n";
    const char *szFName = "env_config.txt";

    FILE *f = fopen(szFName, "w+");
    assert(f != NULL);
    fwrite(szConf, strlen(szConf), 1, f);
    fclose(f);

    VLOOM_EXECV_ENV *env = (VLOOM_EXECV_ENV *)malloc(sizeof(VLOOM_EXECV_ENV));
    vloom_config_readenv(env, szFName);

    CHECK_EQUAL(env->hashfunc_num, 2);
    STRCMP_EQUAL(env->hashfunc_name, "vloom_hash_add32");

    CHECK_EQUAL(env->truncate, 20);

    CHECK_TRUE(env->bloom32);
    CHECK_TRUE(env->blank);
    CHECK_TRUE(env->use32);
    CHECK_TRUE(env->compress);

    STRCMP_EQUAL("log.txt", env->logfile);
    CHECK_EQUAL(4, env->loglevel);

    STRCMP_EQUAL("rtenvfile.txt", env->rtenvfile);
    STRCMP_EQUAL("ffidvfile.txt", env->ffidvfile);

    unlink(szFName);
}

TEST(test_vloomconfig, rtenvlist)
{
    /* generate configuration file */
    const char *szConf = "std::ctype<char>\n"
                         "std::__cxx11::collate<char>\n";
    const char *szFName = "rtenv_list.txt";

    FILE *f = fopen(szFName, "w+");
    assert(f != NULL);
    fwrite(szConf, strlen(szConf), 1, f);
    fclose(f);

    char **list = vloom_config_read_rtenvlist(szFName);
    char **pStr = list;

    STRCMP_EQUAL("std::ctype<char>", *pStr);
    pStr++;
    STRCMP_EQUAL("std::__cxx11::collate<char>", *pStr);
    pStr++;

    CHECK(*pStr == NULL);

    unlink(szFName);
}

TEST(test_vloomconfig, ffidervlist)
{
    /* generate configuration file */
    const char *szConf = "c++class;rustclass;0\n"
                         "c++class2;rustclass2;16\n";
    const char *szFName = "ffderv_list.txt";

    FILE *f = fopen(szFName, "w+");
    assert(f != NULL);
    fwrite(szConf, strlen(szConf), 1, f);
    fclose(f);

    VLOOM_FFIDERV_INFO *ffidInfo = vloom_config_read_ffidervlist(szFName);
    VLOOM_FFIDERV_INFO *info = ffidInfo;

    STRCMP_EQUAL("c++class", info->base_class);
    STRCMP_EQUAL("rustclass", info->derv_class);
    CHECK_EQUAL(0, info->diff_oft);

    info++;
    STRCMP_EQUAL("c++class2", info->base_class);
    STRCMP_EQUAL("rustclass2", info->derv_class);
    CHECK_EQUAL(16, info->diff_oft);

    info++;
    CHECK(NULL == info->base_class);
    CHECK(NULL == info->derv_class);
    CHECK_EQUAL(0, info->diff_oft);

    unlink(szFName);
}

#include <CppUTest/CommandLineTestRunner.h>

int main(int ac, char **av)
{
    return CommandLineTestRunner::RunAllTests(ac, av);
}