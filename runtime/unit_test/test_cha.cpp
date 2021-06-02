#define private public

#include "../cha.h"
#include "../config.h"
#include "../elfmgr.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace std;

TEST_GROUP(test_vloocha){};

/* Save info of an elf symbol */
struct LocalSymbol {
  Elf64_Addr value; /* Symbol value: st_value + info->offset */
  Elf64_Xword size; /* Symbol size: size = st_size */
  const char *name; /* C style symbol name */
};

struct LocalRela {
  Elf64_Addr value; /* Relocation address: r_offset + info->offset */
  const char *name; /* C style symbol name */
};

bool arr2mapSymb(LocalSymbol *arr, map<char *, ElfSymb *> &mapSyms)
{
  ElfSymb *elfsym = NULL;
  for (auto &pair : mapSyms) {
    elfsym = pair.second;
    free(elfsym);
  }
  mapSyms.clear();

  LocalSymbol *sym = arr;
  while (sym->name != NULL) {
    elfsym = (ElfSymb *)malloc(sizeof(ElfSymb) + strlen(sym->name) + 4);
    elfsym->value = sym->value;
    elfsym->size = sym->size;
    strcpy(elfsym->name, sym->name);
    mapSyms.insert({elfsym->name, elfsym});
    sym++;
  }
  return true;
}

bool arr2mapRela(LocalRela *arr, map<char *, ElfRela *> &mapSyms)
{
  ElfRela *elfsym = NULL;
  for (auto &pair : mapSyms) {
    elfsym = pair.second;
    free(elfsym);
  }
  mapSyms.clear();

  LocalRela *sym = arr;
  while (sym->name != NULL) {
    elfsym = (ElfRela *)malloc(sizeof(ElfRela) + strlen(sym->name) + 4);
    elfsym->value = sym->value;
    strcpy(elfsym->name, sym->name);
    mapSyms.insert({elfsym->name, elfsym});
    sym++;
  }
  return true;
}

void visitCHGNodes(VLOOM_CHA *cha)
{
  class EchoCHGInfo : public CHGVisitor {
  public:
    virtual bool visit(CHGNODE *node)
    {
      CHECK_TRUE(node->liVtables != NULL);
      // printf("%s : %s\n", node->pszVtableKeyName, node->demangled);
      return true;
    }
    virtual bool visit(CHGNODE *from, CHGNODE *to, CHGEDGE *edge)
    {
      CHECK_EQUAL(edge->pBaseNode, from);
      CHECK_EQUAL(edge->pDervNode, to);
      // printf("class %s: public %s {};\n", to->pszVtableKeyName, from->pszVtableKeyName);
      return true;
    }
  };

  EchoCHGInfo vtor;
  cha->visitCHGNode(vtor);
  cha->visitCHGTree(vtor);
}

TEST(test_vloocha, DOCHA)
{
  EnvRuntime *envRt = new EnvRuntime(NULL);
  VLOOM_CHA *cha = new VLOOM_CHA(envRt);
  map<char *, ElfSymb *> mapSyms;
  CHGNODE *node = NULL;
  int nVtbl = 0;
  size_t hashID;

  /* vtable */
  LocalSymbol vtblSyms[] = {
      {0x20000, 0, "_ZTV6Vector"},
      {0, 0, 0},
  };
  arr2mapSymb(vtblSyms, mapSyms);
  cha->doAnalyze(&mapSyms, NULL);
  hashID = utils_hashstrs("_ZTV6Vector");
  node = cha->getORaddCHGNode(hashID);
  CHECK_TRUE(node->liVtables != NULL);
  CHECK_TRUE(node->liVtables->next == NULL);

  /* two vtable shares the same name */
  LocalSymbol vtblSymsDup[] = {
      {0x30000, 0, "_ZTV6Vector"},
      {0, 0, 0},
  };
  arr2mapSymb(vtblSymsDup, mapSyms);
  cha->doAnalyze(&mapSyms, NULL);
  CHECK_TRUE(node->liVtables != NULL);
  CHECK_TRUE(node->liVtables->next != NULL);
  CHECK_TRUE(node->liVtables->next->next == NULL);

  LocalSymbol vloomVPTR1[] = {
      {0x11504, 24, "_ZTV3VL1"},
      {0x11576, 24, "_ZTV3VL2"},
      {0x20000, 0, "__VLOOM_VPTR_D11_ZTV6Vector_B11_ZTV6Vector_O16"},

      {0, 0, 0},
  };
  arr2mapSymb(vloomVPTR1, mapSyms);
  CHECK_EQUAL(1, node->nDervClasses);
  cha->doAnalyze(&mapSyms, NULL);
  CHECK_EQUAL(1, node->nDervClasses);
  nVtbl = cha->getCHGNodeNum();
  CHECK_EQUAL(3, nVtbl);

  LocalSymbol vloomVPTR2[] = {
      {0x20000, 0, "__VLOOM_VPTR_D8_ZTV3VL1_B8_ZTV3VL1_O16"},
      {0x20000, 0, "__VLOOM_VPTR_D8_ZTV3VL2_B8_ZTV3VL2_O16"},
      {0x20000, 0, "__VLOOM_VPTR_D8_ZTV3VL1_B11_ZTV6Vector_O16"},
      {0x20000, 0, "__VLOOM_VPTR_D8_ZTV3VL2_B11_ZTV6Vector_O16"},
      {0x20000, 0, "__VLOOM_VPTR_D8_ZTV3VL2_B8_ZTV3VL1_O16"},
      {0, 0, 0},
  };
  arr2mapSymb(vloomVPTR2, mapSyms);
  cha->doAnalyze(&mapSyms, NULL);
  hashID = utils_hashstrs("_ZTV6Vector");
  node = cha->getORaddCHGNode(hashID);
  CHECK_EQUAL(3, node->nDervClasses);
  nVtbl = cha->getCHGNodeNum();
  CHECK_EQUAL(3, nVtbl);

  /* vcall */
  map<char *, ElfRela *> mapRelas;
  LocalRela vloomVCALL[] = {
      {0x20000, "__VLOOM_VCALL_S22_R2_V_ZTV6Vector"},
      {0, 0},
  };
  arr2mapRela(vloomVCALL, mapRelas);
  hashID = utils_hashstrs("_ZTV6Vector");
  node = cha->getORaddCHGNode(hashID);
  CHECK_TRUE(node->liVcalls == NULL);
  cha->doAnalyze(&mapSyms, &mapRelas);
  CHECK_TRUE(node->liVcalls != NULL);

  visitCHGNodes(cha);
  /* used to free mapSyms[i] */
  LocalSymbol dumbSym[] = {
      {0, 0, 0},
  };
  arr2mapSymb(dumbSym, mapSyms);
  LocalRela dumbRela[] = {
      {0, 0},
  };
  arr2mapRela(dumbRela, mapRelas);
  delete cha;
  delete envRt;
}

TEST(test_vloocha, WHITELIST)
{
  /* Generate a config file */
  const char *pConfFile = "del.conf";
  FILE *f = fopen(pConfFile, "w+");
  const char *pszConf = "VLOOM_RTENV_WHLIST:del.rtenv.txt\n"
                        "VLOOM_FFIDRV_WHLIST:del.ffidv.txt\n"
                        "VLOOM_EXTRA_WHLIST:del.extradrv.txt\n";
  fwrite(pszConf, strlen(pszConf), 1, f);
  fclose(f);

  const char *pszENV = "# start a comment\n"
                       "_ZTVSt5ctypeIcE             #std::ctype<char>\n"
                       "_ZTVNSt7__cxx117collateIcEE #std::__cxx11::collate<char>\n";
  f = fopen("del.rtenv.txt", "w+");
  fwrite(pszENV, strlen(pszENV), 1, f);
  fclose(f);

  const char *pszFFI = "#_ZN12cert_storage11CertStorage8allocate6VTABLE17hacb15cbac000e3b5E\n"
                       "#_ZN12cert_storage11CertStorage8allocate6VTABLE17hd9845449574d36dcE\n"
                       "#[xpimplements(nsICertStorage, nsIObserver)]\n"
                       "_ZTV14nsICertStorage;CertStorage;0\n"
                       "_ZTV11nsIObserver;CertStorage;0\n"
                       "_ZTV11nsISupports;CertStorage;0\n";
  f = fopen("del.ffidv.txt", "w+");
  fwrite(pszFFI, strlen(pszFFI), 1, f);
  fclose(f);

  const char *pszExtra = "\n"
                         "_ZTV5nsJAR;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV6nsFind;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV6nsIDTD;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV6nsIURI;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV6nsIURL;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV6nsPipe;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV7nsArray;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV7nsCaret;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV7nsIFile;_ZTV14nsXPTCStubBase;16\n"
                         "_ZTV7nsIFind;_ZTV14nsXPTCStubBase;16\n";
  f = fopen("del.extradrv.txt", "w+");
  fwrite(pszExtra, strlen(pszExtra), 1, f);
  fclose(f);

  EnvConfig *conf = EnvironConf::GetEnvConfig(pConfFile);
  EnvRuntime *envRt = new EnvRuntime(conf);
  VLOOM_CHA *cha = new VLOOM_CHA(envRt);
  cha->doAnalyze(NULL, NULL);
  delete cha;
  delete envRt;
  delete conf;
}

int main(int ac, char **av) { return CommandLineTestRunner::RunAllTests(ac, av); }