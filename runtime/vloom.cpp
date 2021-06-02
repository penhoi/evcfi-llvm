#include "vloom.h"
#include "bloom.h"
#include "cha.h"
#include "config.h"
#include "elfmgr.h"
#include "hash.h"
#include "logging.h"
#include "mm.h"
#include "patch.h"
#include <assert.h>
#include <libgen.h>
#include <link.h>
#include <linux/limits.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

/* config system environment */
EnvConfig *gtEnvConfig = nullptr;
/* The central hub */
VLOOM_Runtime *gVloomRT = nullptr;

/**
 * Initial VLOOM runtime system by providing an environment configuration
 */
VLOOM_Runtime::VLOOM_Runtime(EnvRuntime *rt)
{
  /* initialze gEnvRuntime */
  EnvConfig *env = rt->pEnvConf;
  mEnvRT = rt;

  assert(env != NULL);
  rt->tRuntimeMode = env->tRuntimeMode;

  /* patching related options */
  rt->bAvoidLeaking = env->bAvoidLeaking;
  rt->bR11R10R9 = env->bR11R10R9;

  /* BF related options */
  rt->bBlmFPCentric = env->bBlmFPCentric;
  rt->nHashEntBytes = env->nHashEntBytes;
  rt->nSatLoBound = env->nSatLoBound;
  rt->nSatHiBound = env->nSatHiBound;
  /* Set hash-patch pairs inside .bfConf */
  BloomFilterMgr::FixEnvRuntime(rt);

  /* Update hash-patch pairs inside .paConf */
  CodePatcher::FixEnvRuntime(rt);

  if (env->szSeedFile[0] == '/') // absolute path ?
    rt->pszSeedFile = utils_strdup(env->szSeedFile);
  else {
    char szFile[512];
    char *temp = utils_strdup(rt->pszVloomDSO);
    sprintf(szFile, "%s/%s", dirname(temp), env->szSeedFile);
    rt->pszSeedFile = utils_strdup(szFile);
    free(temp);
  }

  /* Enable deterministic randomize */
  MemMgr::SetRandFile(rt->pszSeedFile);
  rt->pMemMgr = MemMgr::PickInstance();

  /* Initialize VLOOM's ELF file management system */
  mElfMgr = new ElfModuleMgr();

  /* Initialize VLOOM's Class Hierachy Analysis system */
  mCHA = new VLOOM_CHA(rt);

  /* Create BLOOM filter. */
  mBFMgr = BloomFilterMgr::GetBFMgr(rt);

  /* Initialize code patcher */
  mCodePA = CodePatcher::GetPatcher(rt);
}

VLOOM_Runtime::~VLOOM_Runtime()
{
  if (mEnvRT != NULL)
    delete mEnvRT;

  if (mCHA != NULL)
    delete mCHA;
  if (mElfMgr != NULL)
    delete mElfMgr;
  if (mBFMgr != NULL)
    delete mBFMgr;
  if (mCodePA != NULL)
    delete mCodePA;
}

/* Base class of ELF analyzer, a chain of analyzer */
class ElfSymbolVLOOM : public SymbolFilter {
  static const char szVtablePrefix[];
  static const char szVloomPrefix[];
  static const int nVtablePrefix;
  static const int nVloomPrefix;

public:
  virtual bool doFilter(const char *str)
  {
    if (strncmp(str, szVtablePrefix, nVtablePrefix) == 0)
      return true;
    else if (strncmp(str, szVloomPrefix, nVloomPrefix) == 0)
      return true;
    else {
      if (m_next != NULL)
        return m_next->doFilter(str);
      else
        return false;
    }
  }
};
const char ElfSymbolVLOOM::szVtablePrefix[] = {"_ZTV"};
const char ElfSymbolVLOOM::szVloomPrefix[] = {"__VLOOM"};
const int ElfSymbolVLOOM::nVtablePrefix = sizeof(szVtablePrefix) - 1;
const int ElfSymbolVLOOM::nVloomPrefix = sizeof(szVloomPrefix) - 1;

/* hijacked functions */
void *(*VLOOM_Runtime::real_dlopen)(const char *, int) = NULL;
int (*VLOOM_Runtime::real_dlclose)(void *handle) = NULL;

void VLOOM_Runtime::hijack_dl_functions(void)
{
  VLOOM_LOG(VLL_TRACE, "Hijack dlxxx() functions");
  real_dlopen = (void *(*)(const char *, int))dlsym(RTLD_NEXT, "dlopen");
  if (real_dlopen == NULL)
    VLOOM_LOG(VLL_FATAL, "failed to find dlopen() dynamic symbol: %s", strerror(errno));

  real_dlclose = (int (*)(void *))dlsym(RTLD_NEXT, "dlclose");
  if (real_dlclose == NULL)
    VLOOM_LOG(VLL_FATAL, "failed to find dlclose() dynamic symbol: %s", strerror(errno));
}

void VLOOM_Runtime::release_dl_functions(void)
{
  VLOOM_LOG(VLL_TRACE, "Release dlxxx() functions");
  VLOOM_LOG(VLL_TRACE, "I don't want to do it");
}

/**
 * Load code/data segments of all elf files
 */
bool VLOOM_Runtime::loadNewModules(void)
{
  ElfModuleMgr *elfMgr = mElfMgr;

  struct link_map *map = NULL;
  void *handle = real_dlopen(NULL, RTLD_NOW);
  if (handle == NULL)
    VLOOM_LOG(VLL_FATAL, "failed to open main executable: %s", strerror(errno));

  if (dlinfo(handle, RTLD_DI_LINKMAP, &map) < 0 || map == NULL)
    VLOOM_LOG(VLL_FATAL, "failed get linkmap for main: %s", strerror(errno));

  // Load all dynamic libraries:
  char szVLOOM[512], *pVLOOM;
  ElfSymbolVLOOM filter;
  FILE_INFO *fi;

  fi = elfMgr->dlopenExt(mEnvRT->pszMainProg, (ptrdiff_t)map->l_addr, &filter);
  if (!fi)
    VLOOM_LOG(VLL_TRACE, "Failed to load main executable");

  strcpy(szVLOOM, mEnvRT->pszVloomDSO);
  pVLOOM = basename(szVLOOM);
  map = map->l_next;
  while (map != NULL) {
    /* skip VLOOM DSO, we don't want to match the whole path, so not safe */
    if (strstr(map->l_name, pVLOOM) == NULL) {
      fi = elfMgr->dlopenExt(map->l_name, (ptrdiff_t)map->l_addr, &filter);
      if (!fi)
        VLOOM_LOG(VLL_TRACE, "Failed to load library: %s", map->l_name);
    }
    map = map->l_next;
  }
  real_dlclose(handle);

  return true;
}

/**
 * Analysis class hierarchy based on elf symbols
 */
CHGNODE *VLOOM_Runtime::doCHAnalysis(void)
{
  VLOOM_LOG(VLL_TRACE, "Do Class Hierachy Analysis");
  struct link_map *map = NULL;
  void *handle = real_dlopen(NULL, RTLD_NOW);
  assert(handle != NULL);
  dlinfo(handle, RTLD_DI_LINKMAP, &map);

  // class hierachy analysis based on all elf symbols
  // Load all dynamic libraries:
  char szVLOOM[512], *pVLOOM;
  ElfSymbolVLOOM filter;

  strcpy(szVLOOM, mEnvRT->pszVloomDSO);
  pVLOOM = basename(szVLOOM);

  while (map != NULL) {
    /* skip VLOOM DSO, we don't want to match the whole path, so not safe */
    if (strstr(map->l_name, pVLOOM) != NULL) {
      map = map->l_next;
      continue;
    }

    const char *fname;
    if (map->l_name[0] == '\0')
      fname = mEnvRT->pszMainProg;
    else
      fname = map->l_name;

    FILE_INFO *info = mElfMgr->lookupFile(fname);
    if (!info)
      mElfMgr->dlopenExt(fname, (ptrdiff_t)map->l_addr, &filter);

    if (info && !info->testStatus(FILE_INFO::ELFS_ANLYZED)) {
      VLOOM_LOG(VLL_TRACE, "Analyze file %s", fname);
      void *symbs = (void *)mElfMgr->getElfSymbols(info);
      void *relas = (void *)mElfMgr->getElfRelocts(info);
      mCHA->doAnalyze(symbs, relas);
      info->setStatus(FILE_INFO::ELFS_ANLYZED);
    }

    map = map->l_next;
  }
  real_dlclose(handle);

  return mCHA->getUpdatedCHGNodes();
}

/* Schedule the main activies */
int VLOOM_Runtime::schedule(void)
{
  /* Load elf files */
  loadNewModules();

  mCHA->initCHAPass();
  // Class heirarchy analysis on new modules.
  CHGNODE *chain = doCHAnalysis();
  // Update bloom filters for updated CHGNodes
  mBFMgr->updateBloomFilters(mCHA, chain);
  // Apply patches to for updated CHGNodes
  mCodePA->patchInsns(mCHA, chain);

  mCHA->finiCHAPass();
  return true;
}

/* intecept dlopen */
void *dlopen(const char *filename, int flags)
{
  void *handle = VLOOM_Runtime::real_dlopen(filename, flags);
  if (handle != NULL) {
    VLOOM_LOG(VLL_TRACE, "dlopen() called; re-initializing");
    gVloomRT->schedule();
  }

  return handle;
}

/* intecept dlopen */
int dlclose(void *handle)
{
  int res = VLOOM_Runtime::real_dlclose(handle);
  return res;
}

/**
 * Provide this implementation because I don't understand why the original
 * introduces a Loop. Meanwhile, I don't want a fork. The errortic thread should
 * be captured for debuuging.
 */
static void vloom_segv_handler(int sig, siginfo_t *info, void *data) {}

void vloom_SetupSighandler(int _ignored)
{
  /* setup signal handler for segfault */
  VLOOM_LOG(VLL_TRACE, "set signal handler");
  struct sigaction action;

  memset(&action, 0, sizeof(action));
  action.sa_sigaction = vloom_segv_handler;
  action.sa_flags |= SA_SIGINFO;
  sigaction(SIGSEGV, &action, NULL);
}

void vloom_vcfi_init(void)
{
  /* Setup the runtime environment */
  EnvRuntime *envrt = new EnvRuntime(nullptr);

  /* 1. craft the path of configuration file */
  char szConfFile[512];
  char *temp = utils_strdup(envrt->pszVloomDSO);
  // char *temp = utils_strdup(envrt->pszMainProg);
  sprintf(szConfFile, "%s/%s", dirname(temp), "vloomrt.conf");
  free(temp);

  /* 2. get configuration */
  EnvConfig *envConf = EnvironConf::GetEnvConfig(szConfFile);
  if (envConf == NULL)
    VLOOM_LOG(VLL_FATAL, "Fail to get configuration data");
  else
    envrt->pEnvConf = gtEnvConfig = envConf;

  /* Initialize the logging system */
  vloom_LogInit(envConf);

  // #ifdef DEBUG
  // vloom_main(SIGUSR1);
  vloom_SetupSighandler(SIGUSR1);

  /* initialize gVloomRT */
  gVloomRT = new VLOOM_Runtime(envrt);
  gVloomRT->hijack_dl_functions();

  gVloomRT->schedule();

  // #else
  // Sensitive values may leak via the stack.  Thus, we use a temporary stack.
  // size_t size = 32 * VLOOM_PAGE_SIZE;
  // void *temp_stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS |
  // MAP_PRIVATE | MAP_NORESERVE, -1, 0); if (temp_stack == MAP_FAILED)
  // {
  //     VLOOM_LOG(VLL_FATAL, "failed to create a temporary stack: %s",
  //     strerror(errno));
  // }

  // stack_t stack, old_ss;
  // stack.ss_sp = (uint8_t *)temp_stack;
  // stack.ss_flags = 0;
  // stack.ss_size = size;

  // /* setup signal handler */
  // struct sigaction action, old_action;

  // memset(&action, 0, sizeof(action));
  // action.sa_handler = vloom_init_handler;
  // action.sa_flags |= SA_ONSTACK;

  // if (sigaltstack(&stack, &old_ss) < 0)
  //     VLOOM_LOG(VLL_FATAL, "failed to invoke sigaltstack: %s",
  //     strerror(errno));

  // if (sigaction(SIGUSR1, &action, &old_action) < 0)
  //     VLOOM_LOG(VLL_FATAL, "failed to invoke sigaction: %s",
  //     strerror(errno));

  // raise(SIGUSR1);
  // sigaction(SIGUSR1, &old_action, NULL);
  // sigaltstack(&old_ss, NULL);

  // if (munmap(temp_stack, size) < 0)
  // {
  //     VLOOM_LOG(VLL_FATAL, "failed to destroy temporary stack: %s",
  //     strerror(errno));
  // }
  // #endif

  // VLOOM_LOG(VLL_TRACE, "VLOOM is initialized (%zuKB used)",
  // vloom_mm_malloc_used() / 1000);
}

#include <sys/resource.h>
#include <sys/time.h>

void vloom_vcfi_fini(void)
{
  // VLOOM_LOG(VLL_TRACE, "VLOOM is finalized");
  if (gtEnvConfig->bReportMMU) {
    struct rusage buf;
    getrusage(RUSAGE_SELF, &buf);

    VLOOM_LOG(VLL_INFO, "maxRSS: %ld\n", buf.ru_maxrss);
    VLOOM_LOG(VLL_INFO, "minFault: %ld\n", buf.ru_minflt);
    VLOOM_LOG(VLL_INFO, "majFault: %ld\n", buf.ru_majflt);
  }

  gVloomRT->release_dl_functions();
  delete gVloomRT;

  vloom_LogFini();

  if (gtEnvConfig != NULL)
    delete gtEnvConfig;
}

#ifndef VLOOM_UTEST
void __attribute__((constructor)) vloom_init(void) { vloom_vcfi_init(); }

void __attribute__((destructor)) vloom_fini(void) { vloom_vcfi_fini(); }
#endif
