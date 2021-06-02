#define private public

#include "../config.h"
#include <CppUTest/TestHarness.h>
#include <unistd.h>

/****************************************************************************/
/* VLOOM configuration                                                       */
/****************************************************************************/
const char *szConfigFile = "env_config.txt";

TEST_GROUP(test_RuntimeEnvConfig){

};

TEST(test_RuntimeEnvConfig, readenvfromfile)
{
  /* generate configuration file */
  struct keyval {
    const char *key;
    const char *val;
  } arrConf[] = {
      {"VLOOM_MODE", "0"}, // VM_ENFORCE_VCFI
      {"VLOOM_K", "2"},
      {"VLOOM_HASH_0", "add32"},
      {"VLOOM_HASH_1", "add32"},
      {"VLOOM_HASHTABLE_BITS", "24"},
      {"VLOOM_CHECKING_MODE", "0"}, // BFT_COUNTING
      {"VLOOM_COMPRESS_HASHENTRY", "true"},
      {"VLOOM_LOW4G_VTABLE", "true"},
      {"VLOOM_LOW4G_BLOOMF", "true"},
      {"VLOOM_AVOID_LEAKING", "true"},
      {"VLOOM_RANDSEED_FILE", "/dev/urand"},
      {"VLOOM_LOGFILE", "log.txt"},
      {"VLOOM_LOGLEVEL", "4"},
      {"VLOOM_RTENV_WHLIST", "rtenvfile.txt"},
      {"VLOOM_FFIDRV_WHLIST", "ffidvfile.txt"},
      {"VLOOM_EXTRADRV_WHLIST", "extrafile.txt"},
      {NULL, NULL},
  };

  FILE *f = fopen(szConfigFile, "w+");
  CHECK_TRUE(f != NULL);
  char szConf[4096];
  char *pBuf = szConf;
  struct keyval *kv;
  for (kv = arrConf; kv->key != NULL; kv++)
    pBuf += sprintf(pBuf, "%s:%s\n", kv->key, kv->val);

  fwrite(szConf, strlen(szConf), 1, f);
  fclose(f);

  EnvironConf *run = new EnvironConf();
  run->readEnvFromFile(szConfigFile);

  const char *key;
  for (kv = arrConf; kv->key != NULL; kv++) {
    KVPAIR *pair = run->getKVPair(kv->key);
    // if (pair != NULL && pair->K != NULL && pair->V != NULL)
    //     printf("%s:%s\n", pair->K, pair->V);
    CHECK_TRUE(strcmp(kv->val, pair->V) == 0);
  }

  /* do reentry test */
  run->readEnvFromFile(szConfigFile);
  for (kv = arrConf; kv->key != NULL; kv++) {
    KVPAIR *pair = run->getKVPair(kv->key);
    // if (pair != NULL && pair->K != NULL && pair->V != NULL)
    //     printf("%s:%s\n", pair->K, pair->V);
    CHECK_TRUE(strcmp(kv->val, pair->V) == 0);
  }

  /* parse environment variables */
  EnvConfig *ctx = new EnvConfig();
  bool res = run->parseEnvConfig(ctx);
  CHECK_TRUE(res);
  CHECK_EQUAL(2, ctx->nHashNum);
  CHECK_TRUE(strcmp("add32", ctx->arFuncName[0]) == 0);
  CHECK_TRUE(strcmp("add32", ctx->arFuncName[1]) == 0);

  CHECK_TRUE(strcmp("log.txt", ctx->szLogFile) == 0);
  CHECK_TRUE(strcmp("rtenvfile.txt", ctx->szRTenvFile) == 0);

  // delete (run->mEnvCtx);
  delete (ctx);
  delete run;

  /* Test the exported interface */
  ctx = EnvironConf::GetEnvConfig(szConfigFile); // read configurations from file
  CHECK_EQUAL(2, ctx->nHashNum);
  CHECK_TRUE(strcmp("add32", ctx->arFuncName[0]) == 0);
  CHECK_TRUE(strcmp("add32", ctx->arFuncName[1]) == 0);

  CHECK_TRUE(strcmp("log.txt", ctx->szLogFile) == 0);
  CHECK_TRUE(strcmp("rtenvfile.txt", ctx->szRTenvFile) == 0);

  delete (ctx);
  unlink(szConfigFile);
}

TEST(test_RuntimeEnvConfig, readenvfromshell)
{
  EnvironConf *run = new EnvironConf();
  run->readEnvFromShell();

  const char *key, *val;
  KVPAIR *pair;
  int nCnt;

  /* without setting any env-variables */
  pair = run->getKVPair("VLOOM_K");
  CHECK_TRUE(pair == NULL);
  nCnt = run->numVariables();
  CHECK_EQUAL(0, nCnt);

  setenv("VLOOM_K", "2", 1);
  run->readEnvFromShell();
  pair = run->getKVPair("VLOOM_K");
  CHECK_TRUE(pair != NULL && pair->V != NULL);
  CHECK_TRUE(strcmp(pair->V, "2") == 0);
  nCnt = run->numVariables();
  CHECK_EQUAL(1, nCnt);

  setenv("VLOOM_HASH_0", "add32", 1);
  setenv("VLOOM_HASH_1", "add32", 1);
  run->readEnvFromShell();
  pair = run->getKVPair("VLOOM_HASH_0");
  CHECK_TRUE(pair->V != NULL);
  CHECK_TRUE(strcmp(pair->V, "add32") == 0);
  nCnt = run->numVariables();
  CHECK_EQUAL(3, nCnt);

  EnvConfig *ctx = new EnvConfig();
  bool res = run->parseEnvConfig(ctx);
  CHECK_TRUE(res);
  CHECK_EQUAL(2, ctx->nHashNum);
  CHECK_TRUE(strcmp("add32", ctx->arFuncName[0]) == 0);
  CHECK_TRUE(ctx->szLogFile == NULL);

  delete run;
  delete ctx;

  /* test the exported function */
  ctx = EnvironConf::GetEnvConfig(NULL); // read configurations from shell env-variables
  CHECK_EQUAL(2, ctx->nHashNum);
  CHECK_TRUE(strcmp("add32", ctx->arFuncName[0]) == 0);
  CHECK_TRUE(ctx->szLogFile == NULL);
  delete ctx;
}

#include <CppUTest/CommandLineTestRunner.h>

int main(int ac, char **av) { return CommandLineTestRunner::RunAllTests(ac, av); }