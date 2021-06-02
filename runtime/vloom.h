#ifndef __VLOOM_H__
#define __VLOOM_H__

/* functional classes */
struct EnvRuntime;
struct CHGNODE;
class VLOOM_CHA;
class ElfModuleMgr;
class BloomFilterMgr;
class CodePatcher;
/* facet of the VLOOM system */
class VLOOM_Runtime {
private:
  EnvRuntime *mEnvRT; // Runtime of VLOOM system
  VLOOM_CHA *mCHA;
  ElfModuleMgr *mElfMgr;
  BloomFilterMgr *mBFMgr;
  CodePatcher *mCodePA; // code patching actor

public:
  static void *(*real_dlopen)(const char *, int);
  static int (*real_dlclose)(void *handle);

public:
  VLOOM_Runtime(EnvRuntime *rt);
  ~VLOOM_Runtime();

  void hijack_dl_functions(void);
  void release_dl_functions(void);

  /* load elf files */
  bool loadNewModules(void);

  /* Do class hierachy analysis */
  CHGNODE *doCHAnalysis(void);

  /* schedule the main activities */
  int schedule();
};

void vloom_vcfi_init(void);
void vloom_vcfi_fini(void);

#endif // __VLOOM_H__
