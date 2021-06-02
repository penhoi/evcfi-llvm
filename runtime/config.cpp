/**
 * Get configurations set by a confifuration file or shell env-variables
 */
#include "config.h"
#include "bloom.h"
#include "hash.h"
#include "logging.h"
#include "utils.h"
#include <assert.h>
#include <linux/limits.h>
#include <sys/wait.h>
#include <unistd.h>

EnvironConf::EnvironConf()
{
  /* init mEnvCtx */
  mEnvCtx = NULL;

  /* init mEnvMap */
  mEnvMap = new ENVMAP();
}

EnvironConf::~EnvironConf()
{
  /* release mEnvMap: free all memory blocks */
  ENVMAP::iterator it;
  for (it = mEnvMap->begin(); it != mEnvMap->end(); it++) {
    KVPAIR *kv = it->second;
    delete kv;
  }
  delete mEnvMap;
}

/**
 * There too many environment variables to remember, I intend to use a configuration file.
 * @szFName: configuration file
 */
bool EnvironConf::readEnvFromFile(const char *szFName)
{
  assert(szFName != NULL);
  VLOOM_LOG(VLL_TRACE, "Read configuration data from file: %s", szFName);

  char szLine[1024];
  FILE *f;

  f = fopen(szFName, "r");
  if (f == NULL) {
    VLOOM_LOG(VLL_ERROR, "Failed to open file: %s ", szFName);
    return false;
  }

  while (fgets(szLine, 1024, f) != NULL) {
    char *str, *key, *val, *tmp;

    str = utils_trimcomment(szLine);
    if (strlen(str) < 6)
      continue;

    tmp = strchr(str, ':'); // key:val pairs
    if (tmp == NULL) {
      VLOOM_LOG(VLL_ERROR, "Seperate fields in %s with a colon \":\" ", szLine);
      return false;
    }
    else {
      *tmp = 0;
    }

    key = str;
    val = tmp + 1;

    key = utils_trimwhitespace(key);
    val = utils_trimwhitespace(val);
    if ((strlen(key) < 1) || (strlen(val) < 1)) {
      VLOOM_LOG(VLL_ERROR, "key or value is missed within %s", szLine);
      continue;
    }

    addEnvKeyVal(key, val);
  }
  fclose(f);

  return true;
}

/* get the runtime environment by invoking "getenv" */
bool EnvironConf::readEnvFromShell(void)
{
  VLOOM_LOG(VLL_TRACE, "Read configuration data from shell variables");

  const char *arrEnv[] = {
    "VLOOM_MODE",
    "VLOOM_K",
    "VLOOM_HASH_0",
    "VLOOM_HASH_1",
    "VLOOM_HASH_2",
    "VLOOM_HASH_3",
#if (BLOOM_HASH_NUM > 4)
    "VLOOM_HASH_4",
    "VLOOM_HASH_5",
    "VLOOM_HASH_6",
    "VLOOM_HASH_7",
#endif
#if (BLOOM_HASH_NUM > 8)
    "VLOOM_HASH_8",
    "VLOOM_HASH_9",
    "VLOOM_HASH_10",
    "VLOOM_HASH_11",
    "VLOOM_HASH_12",
    "VLOOM_HASH_13",
    "VLOOM_HASH_14",
    "VLOOM_HASH_15",
#endif
    "VLOOM_BLOOM32",
    "VLOOM_FORCE_BLANK",
    "VLOOM_FORCE_32",
    "VLOOM_FORCE_COMPRESS",
    "VLOOM_TRUNCATE",
    "VLOOM_DEBUG",
    "VLOOM_LOGFILE",
    "VLOOM_LOGLEVEL",
    "VLOOM_RTENV_WHLIST",
    "VLOOM_FFIDRV_WHLIST",
    "VLOOM_EXTRA_WHLIST",
    0,
  };
  const char **env = arrEnv;
  const char *K, *V;
  while (*env != NULL) {
    V = getenv(*env);
    if (V != NULL)
      addEnvKeyVal(*env, V);

    env++;
  }
  return true;
}

/**
 * Added new k-v pair; overwrite exisiting ones
 */
bool EnvironConf::addEnvKeyVal(const char *key, const char *val)
{
  /* support reentry */
  ENVMAP::iterator it = mEnvMap->find(key);
  KVPAIR *pair;

  if (it == mEnvMap->end()) {
    assert((key != NULL) && (val != NULL));
    pair = new KVPAIR(key, val);
    mEnvMap->insert({pair->K, pair});
  }
  else {
    pair = it->second;
    if (pair->V != NULL)
      free(pair->V);
    assert(val != NULL);
    pair->V = utils_strdup(val);
  }
  return true;
}

/**
 * Return Environment variable by name
 */
KVPAIR *EnvironConf::getKVPair(const char *key)
{
  ENVMAP::iterator it;

  it = mEnvMap->find(key);
  if (it == mEnvMap->end())
    return NULL;
  else
    return it->second;
}

/**
 * Return Environment variable by name
 */
const char *EnvironConf::getEnvVar(const char *key)
{
  KVPAIR *p = getKVPair(key);

  if (p != NULL)
    return p->V;
  else
    return NULL;
}

size_t EnvironConf::numVariables(void) { return mEnvMap->size(); }

/* convert a string to unsigned long */
bool str2ul(const char *str, int radix, ulong &out)
{
  errno = 0;
  out = strtoul(str, NULL, radix);
  return errno == 0;
}

bool str2float(const char *str, float &out)
{
  errno = 0;
  out = strtof(str, NULL);
  return errno == 0;
}

/**
 * Get execution environment
 * @env: contains all environment variables needed by VLOOM
 */
bool EnvironConf::parseEnvConfig(EnvConfig *env)
{
  assert(env != NULL);
  mEnvCtx = env;

  /* some local data used temporarily */
  const char *var_str;
  const char *szBool;
  bool res;

  var_str = getEnvVar("VLOOM_MODE");
  if (var_str != NULL) {
#define WARN_INVMODED "failed to parse mode; expected an integer from %Y1..%u%D, found \"%s\""
    ulong mode;

    res = str2ul(var_str, 10, mode);
    if (!res || mode >= VM_INVLIAD_MODE)
      VLOOM_LOG(VLL_WARN, WARN_INVMODED, VM_INVLIAD_MODE, var_str);
    else
      mEnvCtx->tRuntimeMode = (RuntimeMode)mode;
  }

  var_str = getEnvVar("VLOOM_K");
  if (var_str != NULL) {
#define WARN_INVK "failed to parse K value; expected an integer from %Y1..%u%D, found \"%s\""
    ulong k;

    res = str2ul(var_str, 10, k);
    if (!res || k > BLOOM_HASH_NUM)
      VLOOM_LOG(VLL_WARN, WARN_INVK, BLOOM_HASH_NUM, var_str);
    else
      mEnvCtx->nHashNum = k;
  }

  /* Hash function name: fix the number of hashfuncs if needs */
  uint real_hashfunc_num = mEnvCtx->nHashNum;
  for (uint i = 0, k = 0; i < mEnvCtx->nHashNum; i++) {
    char szBuf[128];

    snprintf(szBuf, 127, "VLOOM_HASH_%u", i);
    var_str = getEnvVar(szBuf);
    if (var_str != NULL) {
      if (mEnvCtx->arFuncName[k] != NULL)
        free(mEnvCtx->arFuncName[k]);
      mEnvCtx->arFuncName[k] = utils_strdup(var_str);
      k++;
    }
    else
      real_hashfunc_num--;
  }
  if (mEnvCtx->nHashNum != real_hashfunc_num) {
#define WARN_INVFMT "Set environment VLOOM_HASH_0 for the first hash function, VLOOM_HASH_1 for the second, etc..."
    VLOOM_LOG(VLL_WARN, WARN_INVFMT);
  }
  mEnvCtx->nHashNum = real_hashfunc_num;

  if ((szBool = getEnvVar("VLOOM_BFPOLICY_CENTRIC")) != NULL) {
    if (strcmp(szBool, "true") == 0)
      mEnvCtx->bBlmFPCentric = true;
    else if (strcmp(szBool, "false") == 0)
      mEnvCtx->bBlmFPCentric = false;
    else
      _UNREACHABLE;
  }

  /* set nHashTableBits value */
  var_str = getEnvVar("VLOOM_HASHENTRY_BYTE");
  if (var_str != NULL) {
#define MSG_INVHASHENT "failed to parse truncate value; expected an integer from %Y1..%4%D, found \"%s\""
    ulong nBytes;

    res = str2ul(var_str, 10, nBytes);
    if (!res || nBytes > 4 || nBytes < 1)
      VLOOM_LOG(VLL_WARN, MSG_INVHASHENT, var_str);
    else
      mEnvCtx->nHashEntBytes = nBytes;
  }

  /* set nHashTableBits value */
  var_str = getEnvVar("VLOOM_HASHTABLE_BITS");
  if (var_str != NULL) {
#define MSG_INVHASHBITS "failed to parse truncate value; expected an integer from %Y16..%32%D, found \"%s\""
    ulong nBits;

    res = str2ul(var_str, 10, nBits);
    if (!res || nBits > 32 || nBits < 8)
      VLOOM_LOG(VLL_WARN, MSG_INVHASHBITS, var_str);
    else
      mEnvCtx->nHashTableBits = nBits;
  }

  if ((szBool = getEnvVar("VLOOM_AVOID_LEAKING")) != NULL) {
    if (strcmp(szBool, "true") == 0)
      mEnvCtx->bAvoidLeaking = true;
    else if (strcmp(szBool, "false") == 0)
      mEnvCtx->bAvoidLeaking = false;
    else
      _UNREACHABLE;
  }

  var_str = getEnvVar("VLOOM_RANDSEED_FILE");
  if (var_str == NULL)
    var_str = "/dev/urandom";
  mEnvCtx->szSeedFile = utils_strdup(var_str);

  /* logging */
  var_str = getEnvVar("VLOOM_LOGFILE");
  if (var_str == NULL)
    mEnvCtx->szLogFile = NULL;
  else
    mEnvCtx->szLogFile = utils_strdup(var_str);

  /* log level: [debug = 0, debugging, warning = 2, warn, fatal = 4] */
  var_str = getEnvVar("VLOOM_LOGLEVEL");
  if (var_str != NULL) {
    ulong ll;
    res = str2ul(var_str, 10, ll);
    if (res)
      mEnvCtx->nLogLevel = VLOOM_MINVAL(ll, VLL_ERROR);
  }

  var_str = getEnvVar("VLOOM_SATURATION_LOW");
  if (var_str != NULL) {
    float ll;
    res = str2float(var_str, ll);
    if (res)
      mEnvCtx->nSatLoBound = (uint)(1.0001 / ll);
  }

  var_str = getEnvVar("VLOOM_SATURATION_HIGH");
  if (var_str != NULL) {
    float ll;
    res = str2float(var_str, ll);
    if (res)
      mEnvCtx->nSatHiBound = (uint)(1.0001 / ll);
  }

  if ((szBool = getEnvVar("VLOOM_USE_R11R10R9")) != NULL) {
    if (strcmp(szBool, "true") == 0)
      mEnvCtx->bR11R10R9 = true;
    else if (strcmp(szBool, "false") == 0)
      mEnvCtx->bR11R10R9 = false;
    else
      _UNREACHABLE;
  }

  if ((szBool = getEnvVar("VLOOM_REPORT_MMU")) != NULL) {
    if (strcmp(szBool, "true") == 0)
      mEnvCtx->bReportMMU = true;
    else if (strcmp(szBool, "false") == 0)
      mEnvCtx->bReportMMU = false;
    else
      _UNREACHABLE;
  }

  /* white-list file */
  var_str = getEnvVar("VLOOM_RTENV_WHLIST");
  if (var_str == NULL)
    var_str = "rtenv_list.txt";
  mEnvCtx->szRTenvFile = utils_strdup(var_str);

  var_str = getEnvVar("VLOOM_FFIDRV_WHLIST");
  if (var_str == NULL)
    var_str = "ffidv_list.txt";
  mEnvCtx->szFFIdvFile = utils_strdup(var_str);

  var_str = getEnvVar("VLOOM_EXTRA_WHLIST");
  if (var_str == NULL)
    var_str = "extradrv_list.txt";
  mEnvCtx->szExtraFile = utils_strdup(var_str);

  return true;
}

/**
 * @config_file: file contains configuration data;
 * @return: a instance of EnvConfig, user should delete it;
 */
EnvConfig *EnvironConf::GetEnvConfig(const char *config_file)
{
  /* Get the configuration */
  EnvironConf *run = new EnvironConf();

  /* Set number to 1 and function to crc32mul64_v2 by default */
  run->addEnvKeyVal("VLOOM_MODE", "0");
  run->addEnvKeyVal("VLOOM_K", "1");
  run->addEnvKeyVal("VLOOM_HASH_0", "crc32mul64_v2");

  bool res;
  if (access(config_file, F_OK) != -1) // The configuration file is accessbile?
    run->readEnvFromFile(config_file);
  else
    run->readEnvFromShell();

  EnvConfig *env = new EnvConfig();
  run->parseEnvConfig(env);

  delete run;
  return env;
}

/* The runtime environment of VLOOM-RT */
EnvRuntime::EnvRuntime(EnvConfig *conf)
{
  pEnvConf = conf;

  pszMainProg = pszVloomDSO = NULL;
  setProgramPath();
  pszSeedFile = NULL;
}

EnvRuntime::~EnvRuntime(void)
{
  if (arHPs != NULL)
    free(arHPs);
  if (pszMainProg != NULL)
    free(pszMainProg);
  if (pszVloomDSO != NULL)
    free(pszVloomDSO);
  if (pszSeedFile != NULL)
    free(pszSeedFile);
}

#include "dlfcn.h"
#include "libgen.h"
void EnvRuntime::setProgramPath()
{
  /* Get the path of main program */
  const char *self = "/proc/self/exe";
  char path[PATH_MAX + 1];
  const char *fexe;
  ssize_t r = readlink(self, path, sizeof(path) - 1);
  if (r < 0 || r >= sizeof(path) - 1) {
    fexe = self;
  }
  else {
    path[r] = '\0';
    fexe = path;
  }
  pszMainProg = strdup(fexe);

  /* Get the path of VLOOM DSO */
  Dl_info dl_info;
  dladdr((void *)EnvironConf::GetEnvConfig, &dl_info);
  pszVloomDSO = strdup(dl_info.dli_fname);
}