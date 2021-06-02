#include "../elfmgr.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <dlfcn.h>

typedef std::map<const char *, ElfSymb *, STRCMPTOR> MAPSYMB;
typedef std::map<Elf64_Addr, ElfRela *> MAPRELA;

TEST_GROUP(test_elfmgr){};

TEST(test_elfmgr, openclose)
{
  ElfModuleMgr *mgr = new ElfModuleMgr();

  const char *fname = "libVector.so";
  void *handle = dlopen(NULL, RTLD_NOW);
  CHECK(handle != NULL); // assume the file must be dlopened successfully

  FILE_INFO *info = mgr->dlopenExt(fname, 0);
  CHECK_TRUE(info);

  /* reopen the same file */
  int nFiles = mgr->getFileNum();
  CHECK_EQUAL(1, nFiles);

  /* count how many segments have been loaded */
  mgr->loadElfSegments(info);
  int nSeg = mgr->getSegmentNum();
  // CHECK_EQUAL(2, nSeg);

  mgr->dlcloseExt(fname);
  nFiles = mgr->getFileNum();
  CHECK_EQUAL(0, nFiles);
  nSeg = mgr->getSegmentNum();
  CHECK_EQUAL(0, nSeg);
  dlclose(handle);

  delete mgr;
}

/* Base class of ELF analyzer, a chain of analyzer */
class OnlyZTV : public SymbolFilter {
#define vtable_prefix "_ZTV"
public:
  virtual bool doFilter(const char *str)
  {
    if (strncmp(str, vtable_prefix, strlen(vtable_prefix)) == 0)
      return true;
    else
      return false;
  }
};

class OnlyNoZTV : public SymbolFilter {
#define vtable_prefix "_ZTV"
public:
  virtual bool doFilter(const char *str)
  {
    if (!(strncmp(str, vtable_prefix, strlen(vtable_prefix)) == 0))
      return true;
    else
      return false;
  }
};

class OnlyVloom : public SymbolFilter {
#define vloom_prefix "__VLOOM"
public:
  virtual bool doFilter(const char *str)
  {
    if (strncmp(str, vloom_prefix, strlen(vloom_prefix)) == 0)
      return true;
    else
      return false;
  }
};

TEST(test_elfmgr, onSection)
{
  ElfModuleMgr *mgr = new ElfModuleMgr();

  const char *fname = "libVector.so";
  void *handle = dlopen(NULL, RTLD_NOW);
  CHECK(handle != NULL); // assume the file must be dlopened successfully
  FILE_INFO *finfo = mgr->dlopenExt(fname, 0);

  SymbolFilter *filter = NULL;
  MAPSYMB *mapSym = NULL;
  MAPSYMB::iterator iter;
  int all = 0, noztv = 0, onlyztv = 0;

  filter = NULL;
  mapSym = mgr->getElfSymbols(finfo);
  CHECK_TRUE(mapSym != NULL);
  for (auto &pair : *mapSym) {
    // ElfSymb *sym = pair.second;
    // printf("%s\n", pair.first);
    // printf("%s %ld %ld\n", sym->name, sym->value, sym->size);
    all++;
  }
  mgr->dlcloseExt(finfo);

  filter = new OnlyNoZTV();
  finfo = mgr->dlopenExt(fname, 0, filter);
  mapSym = mgr->getElfSymbols(finfo);
  delete filter;
  for (auto &pair : *mapSym) {
    // ElfSymb *sym = pair.second;
    // printf("%s\n", pair.first);
    // printf("%s %ld %ld\n", sym->name, sym->value, sym->size);
    noztv++;
  }
  mgr->dlcloseExt(finfo);

  filter = new OnlyZTV();
  finfo = mgr->dlopenExt(fname, 0, filter);
  mapSym = mgr->getElfSymbols(finfo);
  delete filter;
  for (auto &pair : *mapSym) {
    // ElfSymb *sym = pair.second;
    // printf("%s\n", pair.first);
    // printf("%s %ld %ld\n", sym->name, sym->value, sym->size);

    onlyztv++;
  }
  mgr->dlcloseExt(finfo);

  // CHECK_EQUAL(all, noztv + onlyztv); New version doesn't allow to collect ELF info more than 1 times.

  /* relocation entries */
  filter = new OnlyVloom();
  finfo = mgr->dlopenExt(fname, 0, filter);
  MAPRELA *mapRela = mgr->getElfRelocts(finfo);
  mapSym = mgr->getElfSymbols(finfo);
  delete filter;

  // for (auto &pair : *mapSym)
  //     printf("%s\n", pair.first);
  // for (auto &pair : *mapRela)
  //     printf("%s\n", pair.first);

  for (auto &pair : *mapRela) {
    MAPSYMB::iterator it;
    ElfRela *rel = pair.second;
    it = mapSym->find(rel->name);
    // if (it != mapSym->end())
    // {
    //     ElfSymb *sym = it->second;
    //     printf("Find: %s %ld %ld\n", sym->name, sym->value, sym->size);
    // }
    CHECK_TRUE(it != mapSym->end());
  }

  mgr->dlcloseExt(finfo);
  dlclose(handle);
  delete mgr;
}

int main(int ac, char **av) { return CommandLineTestRunner::RunAllTests(ac, av); }