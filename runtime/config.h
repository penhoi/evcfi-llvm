#ifndef _VLOOM_CONFIG_H__
#define _VLOOM_CONFIG_H__

#include "utils.h"
#include <map>

/* Vloom-runtime mode */
enum RuntimeMode {
  VM_ENFORCE_VCFI,   // enforce vcfi protection
  VM_COUNT_VCALL,    // count the excuted vcalls;
  VM_COUNT_INSNEXEC, // count the excuted VCALLs and RETs;
  VM_PROFILE_CHA,    // profile the details of vloom-rt
  VM_INVLIAD_MODE,
};

/* Runtime environment variables from external */
struct EnvConfig {
  RuntimeMode tRuntimeMode;         // VLOOM Runtime mode
  char *arFuncName[BLOOM_HASH_NUM]; // Designate to use a certain  hash functions
  uint nHashNum;                    // Number of applied hash functions

  bool bBlmFPCentric;  // bloom-filter policy, centric by default
  uint nHashEntBytes;  // BFentry alignment boundary
  uint nHashTableBits; // Hash table size in bit-width
  uint nSatLoBound;
  uint nSatHiBound;

  bool bAvoidLeaking; // Prevent from information leaking.
  bool bR11R10R9;     // use R11R10R9 as sratch registers for patching
  /* report memory usage */
  bool bReportMMU;

  /* Randomization */
  char *szSeedFile;

  /* logging */
  char *szLogFile;
  uint nLogLevel;

  /* white list files */
  char *szFFIdvFile;
  char *szRTenvFile;
  char *szExtraFile;

  EnvConfig(void)
  {
    tRuntimeMode = VM_ENFORCE_VCFI;

    memset(arFuncName, 0, sizeof(char *) * BLOOM_HASH_NUM);
    nHashNum = 0;

    bBlmFPCentric = true;
    nHashEntBytes = 1;
    nHashTableBits = 14; // 4 pages by default
    nSatLoBound = 40;
    nSatHiBound = 4;

    bAvoidLeaking = false; // Blank parameters after use.
    bR11R10R9 = false;
    bReportMMU = false;

    szSeedFile = NULL;
    nLogLevel = 3; // VLL_WARN
    szLogFile = NULL;

    szExtraFile = szRTenvFile = szFFIdvFile = NULL;
  }

  ~EnvConfig()
  {
    for (uint i = 0; i < BLOOM_HASH_NUM; i++) {
      if (arFuncName[i] != NULL)
        free(arFuncName[i]);
    }
    if (szSeedFile != NULL)
      free(szSeedFile);
    if (szLogFile != NULL)
      free(szLogFile);
    if (szFFIdvFile != NULL)
      free(szFFIdvFile);
    if (szRTenvFile != NULL)
      free(szRTenvFile);
    if (szExtraFile != NULL)
      free(szExtraFile);
  }
};

/* setup the runtime environment */
class EnvironConf {
private:
  using ENVMAP = std::map<const char *, KVPAIR *, STRCMPTOR>;
  EnvConfig *mEnvCtx; // Keep results
  ENVMAP *mEnvMap;    // For temporary using

  /* help functions for manipulating mEnvMap */
  bool addEnvKeyVal(const char *key, const char *val);
  KVPAIR *getKVPair(const char *key);
  const char *getEnvVar(const char *key);
  size_t numVariables(void);

  EnvironConf();
  ~EnvironConf();

public:
  /* exported interface function */
  static EnvConfig *GetEnvConfig(const char *config_file);

private:
  /* part1: used for reading into environment variables */
  bool readEnvFromFile(const char *szFName);
  bool readEnvFromShell(void);

  /* part2: parsing environment variables */
  /* parsing enviroment variables */
  bool parseEnvConfig(EnvConfig *env);
};

struct HPFUNCPAIR;
struct EnvRuntime {
  EnvConfig *pEnvConf;
  uint tRuntimeMode;

  /* Information used for patching vcallsites */
  HPFUNCPAIR **arHPs; // Designate to use a certain hash functions
  uint nHashNum;      // Total number of hash functions
  bool bAvoidLeaking; // Blank parameters after use.
  bool bR11R10R9;     // use R11R10R9 as sratch registers for patching
  bool bLoadBFBase;   // One hash function needs to load BF base-address
  uint nScrthRegs;

  /* Information used for setting-up bloom filter */
  bool bBlmFPCentric;   // bloom-filter policy
  uint nHashEntBytes;   // BFentry alignment boundary
  uint nHashTblBits;    // Hash table size in bytes, allocated for BF;
  size_t nHashTblBytes; // Hash table size in bytes, allocated for BF;
  uint nSatLoBound;
  uint nSatHiBound;

  char *pszMainProg; // The path of main program
  char *pszVloomDSO; // The path of this DSO file
  char *pszSeedFile; // seed file for internal randomization

  void *pMemMgr; // secure-memory management of this system;
  EnvRuntime(EnvConfig *conf = nullptr);
  ~EnvRuntime(void);
  void setProgramPath(void);
};

#endif // _VLOOM_CONFIG_H__