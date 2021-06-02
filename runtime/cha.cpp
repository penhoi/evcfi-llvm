#include "cha.h"
#include "config.h"
#include "elfmgr.h"
#include "hash.h"
#include "logging.h"
#include "mm.h"
#include <assert.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <set>

using namespace std;
typedef std::map<const char *, ElfSymb *, STRCMPTOR> MAPSYMB;
typedef std::map<Elf64_Addr, ElfRela *> MAPRELA;

struct VTABLE_PARSE {
  uint32_t nClassID;
  VTABLE_INFO e;
};

struct VCALL_PARSE {
  uint32_t nClassID;
  VCALL_INFO e;
};

struct DERV_INFO {
  char *szBaseClass; // for temporary using
  char *szDervClass; // for temporary using
  size_t nBaseID;    // nBaseID = hash(szBaseClass)
  size_t nDervID;    // nDervID = hash(szDervClass)
  size_t nPtrDiff;
  DERV_INFO(char *base, char *derv)
  {
    szBaseClass = base;
    szDervClass = derv;
    nPtrDiff = nDervID = nBaseID = 0;
  }
};

/* Symbols that passed by CHA may contain prefixes */
const char gszVtablePrefix[] = "_ZTV";
const char gszTypePrefix[] = "_Z";
const char gszVptrPrefix[] = "__VLOOM_VPTR";
const char gszVcallPrefix[] = "__VLOOM_VCALL";
const char gszVRettagtPrefix[] = "__VLOOM_NEXTV";
const char gszThisNextPrefix[] = "__VLOOM_NEXTP";
const char gszDRettagtPrefix[] = "__VLOOM_NEXTD";
const char gszVRetinsnPrefix[] = "__VLOOM_RETV";
const char gszDRetinsnPrefix[] = "__VLOOM_RETD";
const char gszDemangprefix[] = "vtable for ";
const char gszDelim[] = "_PH_";

int gnVtablePrefix = sizeof(gszVtablePrefix) - 1;
int gnTypePrefix = sizeof(gszTypePrefix) - 1;
int gnVptrPrefix = sizeof(gszVptrPrefix) - 1;
int gnVcallPrefix = sizeof(gszVcallPrefix) - 1;
int gnVRettagtPrefix = sizeof(gszVRettagtPrefix) - 1;
int gnThisNextPrefix = sizeof(gszThisNextPrefix) - 1;
int gnDRettagtPrefix = sizeof(gszDRettagtPrefix) - 1;
int gnVRetinsnPrefix = sizeof(gszVRetinsnPrefix) - 1;
int gnDRetinsnPrefix = sizeof(gszDRetinsnPrefix) - 1;
int gnDemangprefix = sizeof(gszDemangprefix) - 1;
int gnDelim = sizeof(gszDelim) - 1;

/* used for debugging */
class VLOOM_SYMBOL {
public:
  char *pKeyName; // Remove prefix;
  char *pRawName; // Raw vloom-symbol
  char *pDmgName; // demanged name
  uint32_t hashID;

private:
  VLOOM_SYMBOL(const char *key_name)
  {
    assert(key_name != NULL);
    pKeyName = utils_strdup(key_name);
    pRawName = pDmgName = NULL;
  }

public:
  ~VLOOM_SYMBOL()
  {
    if (pKeyName != NULL)
      free(pKeyName);
    if (pRawName != NULL)
      free(pRawName);
    if (pDmgName != NULL)
      free(pDmgName);
  }

  static bool Initialize();
  static void Cleanup();

  /* maintain classes */
  static VLOOM_SYMBOL *LookupProcessedClass(size_t ID);
  static VLOOM_SYMBOL *GetOrAddProcessedClass(const char *raw_name, const char *key_name = NULL);

  // maintain functions
  static VLOOM_SYMBOL *LookupProcessedFunc(size_t ID);
  static VLOOM_SYMBOL *GetOrAddProcessedFunc(const char *func_name);

  /* parse the derivation relationship */
  static const char *SkipSymbolPrefix(const char *);

  static bool ParseClangVtblSymbol(const char *strSymbol, VTABLE_PARSE &info);

  static bool ParseRustVtblSymbol(const char *strSymbol, VTABLE_PARSE &info);

  static bool ParseVptrSymbol(const char *strSymbol, DERV_INFO &info);

  static bool ParseVcallSymbol(const char *strSymbol, VCALL_PARSE &info);

  static bool ParseRetinsnSymbol(const char *strSymbol, RETINSN_INFO &info);

  static bool ParseRettagtSymbol(const char *strSymbol, RETTAGT_INFO &info);

  static bool ParseVcallReloct(const char *strSymbol, VCALL_PARSE &info);

private:
  /* manage all the processed symbols */
  static std::map<uint32_t, VLOOM_SYMBOL *> *mapHash2ClassName;
  static std::map<uint32_t, VLOOM_SYMBOL *> *mapHash2FuncName;
};

std::map<uint32_t, VLOOM_SYMBOL *> *VLOOM_SYMBOL::mapHash2ClassName = nullptr;
std::map<uint32_t, VLOOM_SYMBOL *> *VLOOM_SYMBOL::mapHash2FuncName = nullptr;

bool VLOOM_SYMBOL::Initialize()
{
  mapHash2ClassName = new std::map<uint32_t, VLOOM_SYMBOL *>();
  mapHash2FuncName = new std::map<uint32_t, VLOOM_SYMBOL *>();
  return true;
}

void VLOOM_SYMBOL::Cleanup()
{
  /* also need to free mapHash2ClassName */
  for (auto B = mapHash2ClassName->begin(), E = mapHash2ClassName->end(); B != E; B++) {
    VLOOM_SYMBOL *sym = B->second;
    delete sym;
  }
  mapHash2ClassName->clear();
  delete mapHash2ClassName;

  /* also need to free mapHash2FuncName */
  for (auto B = mapHash2FuncName->begin(), E = mapHash2FuncName->end(); B != E; B++) {
    VLOOM_SYMBOL *sym = B->second;
    delete sym;
  }
  mapHash2FuncName->clear();
  delete mapHash2FuncName;
}

/*
 * Skip the prefix of the symbol name
 */
const char *VLOOM_SYMBOL::SkipSymbolPrefix(const char *symbol_name)
{
  const char *name = symbol_name;
  if (strncmp(name, gszVtablePrefix, gnVtablePrefix) == 0)
    return name + gnVtablePrefix;
  if (strncmp(name, gszTypePrefix, gnTypePrefix) == 0)
    return name + gnTypePrefix;
  if (strncmp(name, gszVptrPrefix, gnVptrPrefix) == 0)
    return name + gnVptrPrefix;
  if (strncmp(name, gszVcallPrefix, gnVcallPrefix) == 0)
    return name + gnVcallPrefix;
  if (strncmp(name, gszVRettagtPrefix, gnVRettagtPrefix) == 0)
    return name + gnVRettagtPrefix;
  if (strncmp(name, gszThisNextPrefix, gnThisNextPrefix) == 0)
    return name + gnThisNextPrefix;
  if (strncmp(name, gszDRettagtPrefix, gnDRettagtPrefix) == 0)
    return name + gnDRettagtPrefix;
  if (strncmp(name, gszVRetinsnPrefix, gnVRetinsnPrefix) == 0)
    return name + gnVRetinsnPrefix;
  if (strncmp(name, gszDRetinsnPrefix, gnDRetinsnPrefix) == 0)
    return name + gnDRetinsnPrefix;
  if (strncmp(name, gszDemangprefix, gnDemangprefix) == 0)
    return name + gnDemangprefix;
  return name;
}

VLOOM_SYMBOL *VLOOM_SYMBOL::LookupProcessedClass(size_t ID)
{
  auto it = mapHash2ClassName->find(ID);
  if (it != mapHash2ClassName->end())
    return it->second;
  else
    return nullptr;
}

VLOOM_SYMBOL *VLOOM_SYMBOL::GetOrAddProcessedClass(const char *raw_name, const char *key_name)
{
  assert(mapHash2ClassName != NULL);
  assert(raw_name != NULL);
  if (key_name == NULL)
    key_name = SkipSymbolPrefix(raw_name);

  uint32_t id = utils_hashstrs(key_name);
  VLOOM_SYMBOL *sym = LookupProcessedClass(id);
  if (sym)
    return sym;

  VLOOM_LOG(VLL_TRACE, "Process class: %s -> %s", raw_name, key_name);
  sym = new VLOOM_SYMBOL(key_name);
  sym->hashID = id;
  sym->pRawName = strdup(raw_name);

  char *databuf = (char *)malloc(BUFSIZ);
  size_t len = BUFSIZ;
  int status;
  char *szDmng = abi::__cxa_demangle(raw_name, databuf, &len, &status);
  const char *prefix = gszDemangprefix;
  if (szDmng != NULL) {
    if (strncmp(szDmng, prefix, gnDemangprefix) == 0)
      sym->pDmgName = strdup(szDmng + gnDemangprefix);
    else
      sym->pDmgName = strdup(szDmng);
  }
  else
    sym->pDmgName = strdup(raw_name);
  free(databuf);

  mapHash2ClassName->insert({id, sym});
  return sym;
}

VLOOM_SYMBOL *VLOOM_SYMBOL::LookupProcessedFunc(size_t ID)
{
  auto it = mapHash2FuncName->find(ID);
  if (it != mapHash2ClassName->end())
    return it->second;
  else
    return nullptr;
}

VLOOM_SYMBOL *VLOOM_SYMBOL::GetOrAddProcessedFunc(const char *func_name)
{
  assert(mapHash2FuncName != NULL);
  assert(func_name != NULL);

  uint32_t id = utils_hashstrs(func_name);
  VLOOM_SYMBOL *sym = LookupProcessedFunc(id);
  if (sym)
    return sym;

  VLOOM_LOG(VLL_TRACE, "Process function: %s", func_name);
  sym = new VLOOM_SYMBOL(func_name);
  sym->hashID = id;
  mapHash2FuncName->insert({id, sym});
  return sym;
}

bool VLOOM_SYMBOL::ParseClangVtblSymbol(const char *strSymbol, VTABLE_PARSE &info)
{
  const char *sym = strSymbol;
  auto sb = VLOOM_SYMBOL::GetOrAddProcessedClass(sym);
  if (!sb)
    return false;

  info.nClassID = sb->hashID;
  return true;
}

bool VLOOM_SYMBOL::ParseRustVtblSymbol(const char *strSymbol, VTABLE_PARSE &info)
{
  return ParseClangVtblSymbol(strSymbol, info);
}

/*
 * Parse a special VLOOM VPTR symbol inserted by the compiler.
 * @full_name: the VLOOM_VPTR_ prefix is removed
 * @info: output, has big enough buffer.
 */
bool VLOOM_SYMBOL::ParseVptrSymbol(const char *strSymbol, DERV_INFO &info)
{
  const char *sym = strSymbol;
  char base_name[BUFSIZ];
  char derv_name[BUFSIZ];
  int name_len = BUFSIZ;

  base_name[0] = '\0';
  derv_name[0] = '\0';
  size_t offset = 0;

  while (*sym != '\0') {
    if (*sym != '_')
      return false;
    sym++;
    char c = *sym;
    switch (c) {
    case 'B':
    case 'D':
    case 'O': {
      sym++;
      char *end;
      errno = 0;
      unsigned r = strtoul(sym, &end, 10);
      if (errno != 0 || r >= name_len - 1)
        return false;
      sym = end;
      if (c == 'O') {
        offset = r;
        continue;
      }
      if (strlen(sym) < r)
        return false;
      switch (c) {
      case 'B':
        memcpy(base_name, sym, r);
        base_name[r] = '\0';
        break;
      case 'D':
        memcpy(derv_name, sym, r);
        derv_name[r] = '\0';
        break;
      }
      sym += r;
      break;
    }
    default:
      return false;
    }
  }
  auto sb = VLOOM_SYMBOL::GetOrAddProcessedClass(base_name);
  auto sd = VLOOM_SYMBOL::GetOrAddProcessedClass(derv_name);
  if (!sb || !sd)
    return false;

  info.nPtrDiff = offset;
  info.nBaseID = sb->hashID;
  info.nDervID = sd->hashID;
  return true;
}

/**
 * @brief Parse a special VLOOM VCALL symbol inserted by the compiler.
 *
 * @param strSymbol
 * @param info
 * @return true: if finds a vcall symbols
 * @return false: otherwise
 * w __VLOOM_VCALL_S46_R2_V_ZTV6Vector
 * t __VLOOM_VCALL_S46_R2_V_ZTV6Vector_PH_600be090
 */
bool VLOOM_SYMBOL::ParseVcallSymbol(const char *strSymbol, VCALL_PARSE &info)
{
  char *sym = strdup(strSymbol);
  char *tmp = strstr(sym, gszDelim);
  if (tmp == NULL)
    return false;
  else
    *tmp = '\0';

  bool res = ParseVcallReloct(sym, info);
  delete sym;
  return res;
}

/**
 * @brief
 *
 * @param strSymbol
 * @param info
 * @return true
 * @return false
 * t __VLOOM_RETD_ZTV3VM2_PH_length_PH_1_PH_600be091
 * t __VLOOM_RETV_ZTV4Fake_PH_length_PH_1_PH_600be092
 */
bool VLOOM_SYMBOL::ParseRetinsnSymbol(const char *strSymbol, RETINSN_INFO &info)
{
  char *pCpy, *pSR, *pClassName, *pFuncName, *pArgs, *pID;
  pCpy = strdup(strSymbol);
  pSR = pCpy;

  pClassName = strstr(pSR, gszDelim);
  assert(pClassName != NULL);
  *pClassName = '\0';
  pClassName += gnDelim;

  pFuncName = strstr(pClassName, gszDelim);
  assert(pFuncName != NULL);
  *pFuncName = '\0';
  pFuncName += gnDelim;

  pArgs = strstr(pFuncName, gszDelim);
  assert(pArgs != NULL);
  *pArgs = '\0';
  pArgs += gnDelim;

  pID = strstr(pArgs, gszDelim);
  assert(pID != NULL);
  *pID = '\0';

  // makes the number of parametes as a part of function name
  strcat(pFuncName, pArgs);
  auto sc = VLOOM_SYMBOL::GetOrAddProcessedClass(pClassName);
  auto sf = VLOOM_SYMBOL::GetOrAddProcessedFunc(pFuncName);
  if (!sc || !sf)
    return false;

  info.nClassID = sc->hashID;
  info.nFuncID = sf->hashID;
  info.args = atoi(pArgs);

  char *pTmp = strstr(pSR, "_R");
  assert(pTmp != NULL);
  *pTmp = '\0';
  info.regs = atoi(pTmp + 2);
  info.size = atoi(pSR + 2);

  delete pCpy;
  return true;
}

/**
 * @brief
 *
 * @param strSymbol
 * @param info
 * @return true
 * @return false
 * t __VLOOM_NEXT__ZTV6Vector_PH_length_PH_1_PH_1611391120
 * t __VLOOM_NEXT__ZTV6Vector_PH_length_PH_1_PH_1611391121
 */
bool VLOOM_SYMBOL::ParseRettagtSymbol(const char *strSymbol, RETTAGT_INFO &info)
{
  char *pCpy, *pClassName, *pFuncName, *pArgs, *pID;
  int nSize, nRegs;
  pCpy = strdup(strSymbol);
  pClassName = pCpy;

  pFuncName = strstr(pClassName, gszDelim);
  assert(pFuncName != NULL);
  *pFuncName = '\0';
  pFuncName += gnDelim;

  pArgs = strstr(pFuncName, gszDelim);
  assert(pArgs != NULL);
  *pArgs = '\0';
  pArgs += gnDelim;

  pID = strstr(pArgs, gszDelim);
  assert(pID != NULL);
  *pID = '\0';

  // makes the number of parametes as a part of function name
  strcat(pFuncName, pArgs);
  auto sc = VLOOM_SYMBOL::GetOrAddProcessedClass(pClassName);
  auto sf = VLOOM_SYMBOL::GetOrAddProcessedFunc(pFuncName);
  if (!sc || !sf)
    return false;

  info.nClassID = sc->hashID;
  info.nFuncID = sf->hashID;

  delete pCpy;
  return true;
}

/*
 * Parse a special VLOOM VCALL symbol inserted by the compiler.
 * @sym: input
 * @info: output
 * @return: true if finds a vcall symbols, otherwise false;
 */
bool VLOOM_SYMBOL::ParseVcallReloct(const char *strSymbol, VCALL_PARSE &info)
{
  const char *sym = strSymbol;
  unsigned size = 8, index = 0, regs = 1;
  const char *vtable_name = NULL;
  do {
    if (*sym != '_')
      return false;
    sym++;
    char c = *sym;
    switch (c) {
    case 'S':
    case 'I':
    case 'R': {
      sym++;
      char *end;
      errno = 0;
      unsigned r = strtoul(sym, &end, 10);
      if (errno != 0)
        return false;
      sym = end;
      switch (c) {
      case 'S':
        size = r;
        if (size < 8 || size > 256)
          return false;
        break;
      case 'I':
        index = r;
        if (index > UINT16_MAX)
          return false;
        break;
      case 'R':
        regs = r;
        if (regs > 3)
          return false;
        break;
      }
      break;
    }
    case 'V':
      sym++;
      vtable_name = sym;
      break;
    default:
      sym++;
      break;
    }
  } while (vtable_name == NULL);

  auto s = VLOOM_SYMBOL::GetOrAddProcessedClass(vtable_name);
  if (!s)
    return false;

  info.nClassID = s->hashID;
  info.e.size = size;
  info.e.regs = regs;
  // info.e.nVtableIndx = index;
  return true;
}

/* help functions for debuuging */
VLOOM_SYMBOL *GetVloomSymbol(CHGNODE *entry) { return VLOOM_SYMBOL::LookupProcessedClass(entry->nClassID); }

const char *GetVloomSymbolKeyName(CHGNODE *entry)
{
  VLOOM_SYMBOL *sym = GetVloomSymbol(entry);
  return (!sym) ? nullptr : sym->pKeyName;
}

const char *GetVloomSymbolRawName(CHGNODE *entry)
{
  VLOOM_SYMBOL *sym = GetVloomSymbol(entry);
  return (!sym) ? nullptr : sym->pRawName;
}

const char *GetVloomSymbolDmgName(CHGNODE *entry)
{
  VLOOM_SYMBOL *sym = GetVloomSymbol(entry);
  return (!sym) ? nullptr : sym->pDmgName;
}

/****************************************************************************/
/* VLOOM CLASS HIERACHY ANALYSIS                                            */
/****************************************************************************/
VLOOM_CHA::VLOOM_CHA(EnvRuntime *env)
{
  VLOOM_LOG(VLL_TRACE, "Initialize VLOOM's Class Hierachy Analysis system");
  mMM = (MemMgr *)env->pMemMgr;
  mVloomCHG = RB_INITIALIZER(&mVloomCHG);

  mConf.nHashNum = env->nHashNum;
  if (env->pEnvConf != NULL) {
    mConf.pszFFIdvFile = env->pEnvConf->szFFIdvFile;
    mConf.pszRTenvFile = env->pEnvConf->szRTenvFile;
    mConf.pszExtraFile = env->pEnvConf->szExtraFile;
  }
  else {
    mConf.pszFFIdvFile = NULL;
    mConf.pszRTenvFile = NULL;
    mConf.pszExtraFile = NULL;
  }

  readWhiteLists();
  VLOOM_SYMBOL::Initialize();
}

VLOOM_CHA::~VLOOM_CHA()
{
  for (auto it : mConf.vecRTEnv)
    free(it);
  mConf.vecRTEnv.clear();

  for (auto it : mConf.mapFFIdv) {
    DERV_INFO *info = it.second;
    delete info;
  }
  mConf.mapFFIdv.clear();

  for (auto it : mConf.mapExtra) {
    DERV_INFO *info = it.second;
    delete info;
  }
  mConf.mapExtra.clear();

  VLOOM_SYMBOL::Cleanup();
  VLOOM_LOG(VLL_TRACE, "Finalize VLOOM's Class Hierachy Analysis system");
}

/**
 * This is a critical function to create CHGNodes.
 */
CHGNODE *VLOOM_CHA::getORaddCHGNode(size_t hash_id)
{
  /* Get an existing CHGNODE */
  CHGNODE_ENTRY *ent;
  CHGNODE_ENTRY key;

  key.n.nClassID = (uint32_t)hash_id;
  ent = CHGNODE_TREE_RB_FIND(&mVloomCHG, &key);

  /* return NULL if not find */
  if (ent != NULL)
    return &ent->n;

  /* create new CHGNODE */
  int nBytes = sizeof(CHGNODE_ENTRY) + mConf.nHashNum * sizeof(HASH_PARAM);
  ent = (CHGNODE_ENTRY *)mMM->doMalloc(nBytes);
  ent->n.nClassID = (uint32_t)hash_id;
  CHGNODE *node = &ent->n;
  node->init();

  /* set hash-func paramenters */
  mMM->randBuffer(&node->params, mConf.nHashNum * sizeof(HASH_PARAM));

  /* insert CHGNODE_ENTRY to RB tree */
  CHGNODE_TREE_RB_INSERT(&mVloomCHG, ent);

  /* Each class is a derivied class of itself */
  DERV_INFO info(NULL, NULL);
  info.nDervID = info.nBaseID = hash_id;
  info.nPtrDiff = 16;
  addDerivation(&info);

  return node;
}

int VLOOM_CHA::getCHGNodeNum(void)
{
  CHGNODE_ENTRY *x;
  int num = 0;
  RB_FOREACH(x, CHGNODE_TREE, &mVloomCHG)
  num++;

  return num;
}

/* initialize the internal status for CHA pass */
bool VLOOM_CHA::initCHAPass(void)
{
  mAnalyzedNodes = NULL;
  return true;
}

/* initialize the internal status for CHA pass */
void VLOOM_CHA::finiCHAPass(void)
{
  for (CHGNODE *n = mAnalyzedNodes; n != NULL; n = n->chain)
    n->nStatus = 0; // clear all flags
  mAnalyzedNodes = NULL;
}

/* This node is modified, add it as a part of the CHA result */
void VLOOM_CHA::chainUpdatedCHGNode(CHGNODE *n)
{
  if (!n->bChained) {
    n->chain = mAnalyzedNodes;
    mAnalyzedNodes = n;
    n->bChained = true;
  }
}

/* returns a chain of updated CHGNODEs */
CHGNODE *VLOOM_CHA::getUpdatedCHGNodes(void) { return mAnalyzedNodes; }

/* Major exported interface: analysis class hierachy & parse vcall-sites */
bool VLOOM_CHA::doAnalyze(void *map_symbs, void *map_relas)
{
  bool res = true;

  if (map_symbs != NULL) {
    for (auto &pair : *(MAPSYMB *)map_symbs) {
      enum SymbolType {
        ST_UNKNOW = 0,
        ST_VTABLE_ITANIUM,
        ST_VTABLE_RUST,
        ST_DERIVATION_CXX,
      };

      ElfSymb *sym = pair.second;
      char *symName = sym->name;
      SymbolType st = ST_UNKNOW;

      /* VTABLE respect the itanium-cxx-abi? */
      if (strncmp(symName, gszVtablePrefix, gnVtablePrefix) == 0)
        _doClangVtableAnalysis(sym, symName);
      // Class derivation symbol?
      else if (strncmp(symName, gszVptrPrefix, gnVptrPrefix) == 0)
        _doVptrAnalysis(sym, symName);
      else if (strncmp(symName, gszVcallPrefix, gnVcallPrefix) == 0)
        _doVCallAnalysis(sym, symName);
      else if (strncmp(symName, gszVRettagtPrefix, gnVRettagtPrefix) == 0)
        _doVRettagtAnalysis(sym, symName);
      else if (strncmp(symName, gszDRettagtPrefix, gnDRettagtPrefix) == 0)
        _doDRettagtAnalysis(sym, symName);
      else if (strncmp(symName, gszThisNextPrefix, gnThisNextPrefix) == 0)
        _doThisNextAnalysis(sym, symName);
      else if (strncmp(symName, gszVRetinsnPrefix, gnVRetinsnPrefix) == 0)
        _doVRetinsnAnalysis(sym, symName);
      else if (strncmp(symName, gszDRetinsnPrefix, gnDRetinsnPrefix) == 0)
        _doDRetinsnAnalysis(sym, symName);
      // VTABLE defined by rust code?
      else if (strstr(symName, "8allocate6VTABLE") != NULL)
        _doRustVtableAnalysis(sym, symName);
      else
        VLOOM_LOG(VLL_TRACE, "Unused symbol %s", symName);
    }
  }

  if (map_relas != NULL)
    res &= _doVCallAnalysis(map_relas);

  return res;
}

bool VLOOM_CHA::_doClangVtableAnalysis(ElfSymb *sym, const char *symbol)
{
  // assert((symbol != NULL) && (strncmp(...) == 0));
  const char *infocode = symbol;
  VTABLE_PARSE ps;
  if (!VLOOM_SYMBOL::ParseClangVtblSymbol(infocode, ps))
    return false;

  auto sc = VLOOM_SYMBOL::LookupProcessedClass(ps.nClassID);
  // assert(sc);

  // VTABLEs may be defined in multiple locations.  Let ld.so decide:
  uint8_t *vtable = (uint8_t *)dlsym(RTLD_DEFAULT, symbol);
  if (vtable == NULL) // The symbol is not dynamic:
    vtable = (uint8_t *)sym->value;

  if ((ulong)vtable < VLOOM_MIN_CODEADDR) { // An invalid address
    VLOOM_LOG(VLL_WARN, "Why %s has a VTABLE @%p ?", sc->pKeyName, vtable);
    return false;
  }

  CHGNODE *n = getORaddCHGNode(ps.nClassID);
  ps.e.addr = vtable;
  ps.e.size = sym->size;
  addVtable(n, &ps.e);
  return true;
}

bool VLOOM_CHA::_doRustVtableAnalysis(ElfSymb *sym, const char *symbol)
{
  // assert((symbol != NULL) && (strncmp(...) == 0));
  const char *infocode = symbol;
  VTABLE_PARSE ps;
  if (!VLOOM_SYMBOL::ParseRustVtblSymbol(infocode, ps))
    return false;

  auto sc = VLOOM_SYMBOL::LookupProcessedClass(ps.nClassID);
  // assert(sc);

  // VTABLEs may be defined in multiple locations.  Let ld.so decide:
  uint8_t *vtable = (uint8_t *)dlsym(RTLD_DEFAULT, symbol);
  if (vtable == NULL) // The symbol is not dynamic:
    vtable = (uint8_t *)sym->value;

  if ((ulong)vtable < VLOOM_MIN_CODEADDR) { // An invalid address
    VLOOM_LOG(VLL_WARN, "Why %s has a VTABLE @%p ?", sc->pKeyName, vtable);
    return false;
  }

  CHGNODE *n = getORaddCHGNode(ps.nClassID);
  ps.e.addr = vtable;
  ps.e.size = sym->size;
  addVtable(n, &ps.e);

  /* Dealing with whitelist type 1:
   * Add class derivations between two different languages, i.e. Rust and C++;
   */
  for (auto it : mConf.mapFFIdv) {
    DERV_INFO *pInfo = it.second;
    if (strstr(sc->pKeyName, pInfo->szDervClass) != NULL) {
      /** fix-me **/
      pInfo->nBaseID = utils_hashstrs(pInfo->szBaseClass);
      pInfo->nDervID = ps.nClassID;
      addDerivation(pInfo);
    }
  }
  return true;
}

bool VLOOM_CHA::_doVptrAnalysis(ElfSymb *sym, const char *symbol)
{
  const char *infocode = symbol + gnVptrPrefix;
  /* check derivation */
  DERV_INFO info(NULL, NULL);
  if (VLOOM_SYMBOL::ParseVptrSymbol(infocode, info)) {
    // if (strcmp(derived_name, "_ZTV14nsXPTCStubBase") == 0)
    //     _UNREACHABLE;
    CHGNODE *baseNode = getORaddCHGNode(info.nBaseID);
    assert(baseNode != NULL);
    baseNode->bVerified = true;

    CHGNODE *dervNode = getORaddCHGNode(info.nDervID);
    assert(dervNode != NULL);
    dervNode->bVerified = true;

    addDerivation(&info);
  }
  return true;
}

// full symbol: __VLOOM_VCALL_S64_R3_V_ZTV6Vector
bool VLOOM_CHA::_doVCallAnalysis(ElfSymb *sym, const char *symbol)
{
#define VCALLS_MSG "virtual call found for class %G%s%D at location %Y%p%D"
  // assert((symbol != NULL) && (strncmp(...) == 0));
  const char *infocode = symbol + gnVcallPrefix;
  VCALL_PARSE ps;
  if (!VLOOM_SYMBOL::ParseVcallSymbol(infocode, ps))
    return false;

  CHGNODE *entry = getORaddCHGNode(ps.nClassID);
  // assert(entry != NULL);

  // VTABLEs may be defined in multiple locations.  Let ld.so decide:
  uint8_t *addr = (uint8_t *)dlsym(RTLD_DEFAULT, symbol);
  if (addr == NULL) // The symbol is not dynamic:
    addr = (uint8_t *)sym->value;

  if ((ulong)addr < VLOOM_MIN_CODEADDR) { // An invalid address
    auto sc = VLOOM_SYMBOL::LookupProcessedClass(ps.nClassID);
    VLOOM_LOG(VLL_WARN, "Why %s has a VCALL @%p ?", sc->pKeyName, addr);
    return false;
  }

  // Record this location to be patched later (after CHA).
  VLOOM_LOG(VLL_TRACE, VCALLS_MSG, KEYNAME(entry), addr);
  ps.e.addr = addr;
  addVCallSite(entry, &ps.e);

  return true;
}

enum NEXT_LABLE_TYPE {
  NLABTY_V,
  NLABTY_D,
  NLABTY_P,
};

// full symbol: __VLOOM_NEXTV__ZTV3VL1_PH_VL1_PH_3_PH_1611132256
bool VLOOM_CHA::_doVRettagtAnalysis(ElfSymb *symm, const char *symbol)
{
  return _doRettagtAnalysis(symm, symbol, NLABTY_V);
}

// full symbol: __VLOOM_NEXTD__ZTV3VL1_PH_VL1_PH_3_PH_1611132256
bool VLOOM_CHA::_doDRettagtAnalysis(ElfSymb *sym, const char *symbol)
{
  return _doRettagtAnalysis(sym, symbol, NLABTY_D);
}

bool VLOOM_CHA::_doThisNextAnalysis(ElfSymb *sym, const char *symbol)
{
  return _doRettagtAnalysis(sym, symbol, NLABTY_P);
}

bool VLOOM_CHA::_doRettagtAnalysis(ElfSymb *sym, const char *symbol, int type)
{
#define RETSTV_MSG "RetV target found for class %G%s%D at location %Y%p%D"
#define RETSTD_MSG "RetD target found for class %G%s%D at location %Y%p%D"
#define THISNXT_MSG "A ThisNext found for class %G%s%D at location %Y%p%D"
  const char *infocode = symbol + gnVRettagtPrefix; // the same as gnDRettagtPrefix
  RETTAGT_INFO ps;
  bool res = VLOOM_SYMBOL::ParseRettagtSymbol(infocode, ps);
  if (!res)
    return false;

  // VTABLEs may be defined in multiple locations.  Let ld.so decide:
  uint8_t *addr = (uint8_t *)dlsym(RTLD_DEFAULT, symbol);
  if (addr == NULL) // The symbol is not dynamic:
    addr = (uint8_t *)sym->value;

  if ((ulong)addr < VLOOM_MIN_CODEADDR) { // An invalid address
    auto sc = VLOOM_SYMBOL::LookupProcessedClass(ps.nClassID);
    VLOOM_LOG(VLL_WARN, "Why %s has a RET-target @%p ?", sc->pKeyName, addr);
    return false;
  }

  // Record this location to be patched later (after CHA).
  ps.addr = addr;
  CHGNODE *entry = getORaddCHGNode(ps.nClassID);
  // assert(entry != NULL);
  switch (type) {
  case NLABTY_V:
    VLOOM_LOG(VLL_TRACE, RETSTV_MSG, KEYNAME(entry), addr);
    break;
  case NLABTY_D:
    VLOOM_LOG(VLL_TRACE, RETSTD_MSG, KEYNAME(entry), addr);
    break;
  case NLABTY_P:
    VLOOM_LOG(VLL_TRACE, THISNXT_MSG, KEYNAME(entry), addr);
    break;
  default:
    _UNREACHABLE;
  }

  addRetTagt(entry, &ps, type);

  return true;
}

bool VLOOM_CHA::_doVRetinsnAnalysis(ElfSymb *symm, const char *symbol)
{
  return _doRetinsnAnalysis(symm, symbol, true);
}
bool VLOOM_CHA::_doDRetinsnAnalysis(ElfSymb *sym, const char *symbol)
{
  return _doRetinsnAnalysis(sym, symbol, false);
}

bool VLOOM_CHA::_doRetinsnAnalysis(ElfSymb *sym, const char *symbol, bool bVMethod)
{
#define RETINV_MSG "RetV instruction found for class %G%s%D at location %Y%p%D"
#define RETIND_MSG "RetD instruction found for class %G%s%D at location %Y%p%D"
  const char *infocode = symbol + gnVRetinsnPrefix; // the same as gnDRetinsnPrefix
  RETINSN_INFO ps;
  bool res = VLOOM_SYMBOL::ParseRetinsnSymbol(infocode, ps);
  if (!res)
    return false;

  // VTABLEs may be defined in multiple locations.  Let ld.so decide:
  uint8_t *addr = (uint8_t *)dlsym(RTLD_DEFAULT, symbol);
  if (addr == NULL) // The symbol is not dynamic:
    addr = (uint8_t *)sym->value;
  if ((ulong)addr < VLOOM_MIN_CODEADDR) { // An invalid address
    auto sc = VLOOM_SYMBOL::LookupProcessedClass(ps.nClassID);
    VLOOM_LOG(VLL_WARN, "Why %s has a RET-target @%p ?", sc->pKeyName, addr);
    return false;
  }

  // Record this location to be patched later (after CHA).
  ps.addr = addr;
  CHGNODE *entry = getORaddCHGNode(ps.nClassID);
  // assert(entry != NULL);

  if (bVMethod)
    VLOOM_LOG(VLL_TRACE, RETINV_MSG, KEYNAME(entry), addr);
  else
    VLOOM_LOG(VLL_TRACE, RETIND_MSG, KEYNAME(entry), addr);
  addRetInsn(entry, &ps, bVMethod);

  return true;
}

/**
 * Return a chain of CHGNODE, whose information is updated,
 * and therefore BLOOM should be updated accordingly
 */
// bool VLOOM_CHA::_doClassAnalysis(void *map_symbs) {
//   /* Dealing with whitelist first */
//   if (mConf.vecRTEnv.size() > 0) {
//     /* Add VTABLEs for objects defined in runtime-environment like libc.so */
//     std::vector<char *> remaind;
//     for (auto pStr : mConf.vecRTEnv) {
//       void *vtable = (uint8_t *)dlsym(RTLD_DEFAULT, pStr);
//       if (vtable != NULL) {
//         size_t hashid = utils_hashstrs(pStr);
//         vtable = (void *)((ulong)vtable + 16); // rtii + vptr_diff
//         addVtable(hashid, vtable, sizeof(void *) + 16);
//         free(pStr);
//       } else
//         remaind.push_back(pStr);
//     }
//     mConf.vecRTEnv = remaind;
//   }

//   if (mConf.mapExtra.size() > 0) {
//     /* Add extra derivation relationships defined in white-list file */
//     for (auto it : mConf.mapExtra) {
//       DERV_INFO *pInfo = it.second;
//       addDerivation(pInfo);
//       delete pInfo;
//     }
//     mConf.mapExtra.clear();
//   }

//   /* others */
//   MAPSYMB *mapSymbs = (MAPSYMB *)map_symbs;
//   if (mapSymbs == NULL)
//     return false;

//   for (auto &pair : *mapSymbs) {
//     enum SymbolType {
//       ST_UNKNOW = 0,
//       ST_VTABLE_ITANIUM,
//       ST_VTABLE_RUST,
//       ST_DERIVATION_CXX,
//     };

//     ElfSymb *sym = pair.second;
//     char *symName = sym->name;
//     SymbolType st = ST_UNKNOW;

//     /* VTABLE respect the itanium-cxx-abi? */
//     if (strncmp(symName, gszVtablePrefix, gnVtablePrefix) == 0)
//       st = ST_VTABLE_ITANIUM;
//     // VTABLE defined by rust code?
//     else if (strstr(symName, "8allocate6VTABLE") != NULL)
//       st = ST_VTABLE_RUST;
//     // Class derivation symbol?
//     else if (strncmp(symName, gszVptrPrefix, gnVptrPrefix) == 0)
//       st = ST_DERIVATION_CXX;
//     else
//       st = ST_UNKNOW;

//     switch (st) {
//     case ST_VTABLE_ITANIUM:
//     case ST_VTABLE_RUST: {
//       // VTABLEs may be defined in multiple locations.  Let ld.so decide:
//       void *vtable = (uint8_t *)dlsym(RTLD_DEFAULT, symName);
//       if (vtable == NULL) { // The symbol is not dynamic:
//         vtable = (uint8_t *)sym->value;
//       }

//       if ((ulong)vtable < VLOOM_MIN_CODEADDR) { // An invalid address
//         VLOOM_LOG(VLL_WARN, "Why %s has a VTABLE @%p ?", symName, vtable);
//         continue;
//       }
//       size_t hashid = utils_hashstrs(symName);
//       addVtable(hashid, vtable, sym->size);
//     } break;

//     case ST_DERIVATION_CXX: {
//       /* check derivation */
//       DERV_INFO *info = new DERV_INFO(NULL, NULL);
//       info->szBaseClass = (char *)malloc(BUFSIZ);
//       info->szDervClass = (char *)malloc(BUFSIZ);
//       if (VLOOM_SYMBOL::ParseVptrSymbol(symName, *info)) {
//         // if (strcmp(derived_name, "_ZTV14nsXPTCStubBase") == 0)
//         //     asm("int3");
//         addDerivation(info);
//       }
//       delete info;
//     } break;

//     default:
//       break;
//     } // end switch

//     /* Dealing with whitelist type 1:
//      * Add class derivations between two different languages, such as Rust
//      and
//      * C++
//      * */
//     if (st == ST_VTABLE_RUST) {
//       for (auto it : mConf.mapFFIdv) {
//         DERV_INFO *pInfo = it.second;
//         if (strstr(symName, pInfo->szDervClass) != NULL) {
//           addDerivation(pInfo);
//         }
//       }
//     }
//   } // end for

//   return true;
// }

/** Find out all vcalls from relocation entries
 *
 */
bool VLOOM_CHA::_doVCallAnalysis(void *map_relas)
{
  assert(map_relas != NULL);
  MAPRELA *mapRelas = (MAPRELA *)map_relas;

  for (auto &pair : *mapRelas) {
#define VCALLR_MSG "virtual call found for class %G%s%D at location %Y%p%D"
    ElfRela *rela = pair.second;
    const char *sym = rela->name;
    if (strncmp(sym, gszVcallPrefix, gnVcallPrefix) != 0)
      continue;
    else
      sym += gnVcallPrefix;

    VCALL_PARSE vcall;
    if (!VLOOM_SYMBOL::ParseVcallReloct(sym, vcall)) // not a vcall-symbol ?
      continue;

    CHGNODE *entry = getORaddCHGNode(vcall.nClassID);
    assert(entry != NULL);

    // Record this location to be patched later (after CHA).
    uint8_t *ptr = (uint8_t *)(rela->value + sizeof(uint64_t));
    VLOOM_LOG(VLL_TRACE, VCALLR_MSG, KEYNAME(entry), ptr);
    vcall.e.addr = ptr;
    addVCallSite(entry, &vcall.e);
  }

  return true;
}

/*
 * Add an inheritage relationship:
 * convert a DERV_INFO instance to a CHGEDGE instance;
 */
CHGEDGE *VLOOM_CHA::addDerivation(DERV_INFO *info)
{
#define MSG_DERV_INFO "detected %G%s::VPTR%D with offset %Y+%zu%D into %G%s::VTABLE%D"
  CHGNODE *baseNode = getORaddCHGNode(info->nBaseID);
  assert(baseNode != NULL);

  CHGNODE *dervNode = getORaddCHGNode(info->nDervID);
  assert(dervNode != NULL);

  CHGEDGE_ENTRY *edge_entry = NULL;
  CHGEDGE_ENTRY key;
  key.e.pBaseNode = baseNode;
  key.e.pDervNode = dervNode;
  key.e.nPtrDiff = info->nPtrDiff;

  edge_entry = CHGEDGE_TREE_RB_FIND(&baseNode->trDervClasses, &key);
  if (edge_entry != NULL) // Already exist
    return &edge_entry->e;

  /* add new edge */
  VLOOM_LOG(VLL_TRACE, MSG_DERV_INFO, KEYNAME(baseNode), info->nPtrDiff, KEYNAME(dervNode));
  edge_entry = (CHGEDGE_ENTRY *)mMM->doMalloc(sizeof(CHGEDGE_ENTRY));
  CHGEDGE &e = edge_entry->e;
  e.pBaseNode = baseNode;
  e.pDervNode = dervNode;
  e.nPtrDiff = info->nPtrDiff;

  CHGEDGE_TREE_RB_INSERT(&baseNode->trDervClasses, edge_entry);
  baseNode->nDervClasses++;

  /* add another ancestor to dervNode */
  ADDR_CHAIN *anct = (ADDR_CHAIN *)mMM->doMalloc(sizeof(ADDR_CHAIN));
  anct->addr = baseNode;
  anct->next = dervNode->liAncestors;
  dervNode->liAncestors = anct;
  dervNode->nAncestors++;
  dervNode->bNewAncestor = true;
  chainUpdatedCHGNode(dervNode);

  baseNode->bNewDervCls = true;
  chainUpdatedCHGNode(baseNode);

  return &edge_entry->e;
}

VTABLE_INFO *VLOOM_CHA::addVtable(CHGNODE *entry, VTABLE_INFO *info)
{
#define MSG_DUP_SYMBOL "duplicate symbol table entry detected for %G%s%D -> %G%s%D, use %p not %p"
#define MSG_DUP_NAME "The same class name %G%s%D is used by vtable @ %p"
#define MSG_CREATE_NODE "detected %G%s::VTABLE%D with size %zu at address %p"
  assert(entry != NULL);

  void *vtable_addr = info->addr;
  size_t size = info->size;
  if (vtable_addr == NULL)
    return NULL;

  VTABLE_INFO *tbl = entry->liVtables;
  bool bExist = false;

  while ((tbl != NULL) && !bExist) {
    if (tbl->addr == vtable_addr)
      bExist = true;
    else
      tbl = tbl->next;
  }

  if (bExist)
    return tbl;

  // Create new entry
  VTABLE_INFO *newTbl = (VTABLE_INFO *)mMM->doMalloc(sizeof(VTABLE_INFO));
  memcpy(newTbl, info, sizeof(VTABLE_INFO));
  newTbl->next = entry->liVtables;
  entry->liVtables = newTbl;
  entry->nVtables++;

  VLOOM_LOG(VLL_TRACE, MSG_CREATE_NODE, KEYNAME(entry), size, newTbl->addr);
  if (entry->nVtables > 1) {
    for (VTABLE_INFO *vt = entry->liVtables; vt != NULL; vt = vt->next)
      VLOOM_LOG(VLL_WARN, MSG_DUP_NAME, KEYNAME(entry), vt->addr);
  }
  entry->bNewVtable = true;
  chainUpdatedCHGNode(entry);

  return newTbl;
}

/*
 * Add a patch location, the status of CHGNODE would be changed.
 */
VCALL_INFO *VLOOM_CHA::addVCallSite(CHGNODE *entry, VCALL_INFO *info)
{
  size_t nBytes = sizeof(VCALL_INFO) + mConf.nHashNum * sizeof(HASH_PARAM);
  VCALL_INFO *patch = (VCALL_INFO *)mMM->doMalloc(nBytes);
  memcpy(patch, info, sizeof(VCALL_INFO));
  mMM->randBuffer(&patch->params, mConf.nHashNum * sizeof(HASH_PARAM));

  patch->next = entry->liVcalls;
  entry->liVcalls = patch;
  entry->nVcalls++;

  entry->bNewVCall = true;
  chainUpdatedCHGNode(entry);

  return patch;
}

RETTAGT_INFO *VLOOM_CHA::addRetTagt(CHGNODE *entry, RETTAGT_INFO *info, int type)
{
  if (type == NLABTY_P) {
    ADDR_CHAIN *node = (ADDR_CHAIN *)mMM->doMalloc(sizeof(ADDR_CHAIN));
    node->addr = info->addr;
    node->next = entry->liThisNexts;
    entry->liThisNexts = node;

    entry->nThisNexts++;
    entry->bNewThisNext = true;
    chainUpdatedCHGNode(entry);
    return NULL;
  }

  RETTAGT_TREE *tr;
  if (type == NLABTY_V)
    tr = &entry->trVRetTagts;
  else
    tr = &entry->trDRetTagts;
  RETTAGT_ENTRY key, *ent;

  key.e.nFuncID = info->nFuncID;
  ent = RETTAGT_TREE_RB_FIND(tr, &key);
  if (ent == NULL) {
    // create new node, just malloc once for two objects
    int nBytes = sizeof(RETTAGT_ENTRY) + sizeof(ADDR_CHAIN);
    ent = (RETTAGT_ENTRY *)mMM->doMalloc(nBytes);
    RETTAGT_INFO &tagt = ent->e;
    ADDR_CHAIN *node = (ADDR_CHAIN *)((long)ent + nBytes - sizeof(ADDR_CHAIN));

    memcpy(&tagt, info, sizeof(RETTAGT_INFO));
    node->addr = info->addr;
    node->next = NULL;
    tagt.chain = node;
    // do insert-op after all above things done if you don't want to have a bug
    RETTAGT_TREE_RB_INSERT(tr, ent);

    if (type == NLABTY_V) {
      entry->bNewVRetTagt = true;
      entry->nVRetTagts++;
    }
    else {
      entry->bNewDRetTagt = true;
      entry->nDRetTagts++;
    }
    chainUpdatedCHGNode(entry);
  }
  else {
    // Already exist the give function type, ensure no duplicated ones
    ADDR_CHAIN *node = ent->e.chain;
    bool bExist = false;
    while ((node != NULL) && !bExist) {
      if (node->addr == info->addr)
        bExist = true;
      else
        node = node->next;
    }
    if (!bExist) { // add new node into the chain
      node = (ADDR_CHAIN *)mMM->doMalloc(sizeof(ADDR_CHAIN));
      node->addr = info->addr;
      node->next = ent->e.chain;
      ent->e.chain = node;
      if (type == NLABTY_V) {
        entry->bNewVRetTagt = true;
        entry->nVRetTagts++;
      }
      else {
        entry->bNewDRetTagt = true;
        entry->nDRetTagts++;
      }
      chainUpdatedCHGNode(entry);
    }
  }

  return &ent->e;
}

RETINSN_INFO *VLOOM_CHA::addRetInsn(CHGNODE *entry, RETINSN_INFO *info, bool bVMethod)
{
  RETINSN_TREE *tr;
  if (bVMethod)
    tr = &entry->trVRetInsns;
  else
    tr = &entry->trDRetInsns;
  RETINSN_ENTRY key, *ent;

  key.e.nFuncID = info->nFuncID;
  ent = RETINSN_TREE_RB_FIND(tr, &key);
  if (ent == NULL) {
    // create new node, just malloc once for two objects
    int nBytes = sizeof(RETINSN_ENTRY) + mConf.nHashNum * sizeof(HASH_PARAM) + sizeof(ADDR_CHAIN);
    ent = (RETINSN_ENTRY *)mMM->doMalloc(nBytes);
    RETINSN_INFO &insn = ent->e;
    ADDR_CHAIN *node = (ADDR_CHAIN *)((long)ent + nBytes - sizeof(ADDR_CHAIN));

    memcpy(&insn, info, sizeof(RETINSN_INFO));
    mMM->randBuffer(&insn.params, mConf.nHashNum * sizeof(HASH_PARAM));
    node->addr = info->addr;
    node->next = NULL;
    insn.chain = node;
    RETINSN_TREE_RB_INSERT(tr, ent);

    if (bVMethod) {
      entry->bNewVRetInsn = true;
      entry->nVRetInsns++;
    }
    else {
      entry->bNewDRetInsn = true;
      entry->nDRetInsns++;
    }
    chainUpdatedCHGNode(entry);
  }
  else {
    // Already exist the give function type, ensure no duplicated ones
    ADDR_CHAIN *node = ent->e.chain;
    bool bExist = false;
    while ((node != NULL) && !bExist) {
      if (node->addr == info->addr)
        bExist = true;
      else
        node = node->next;
    }
    if (!bExist) { // add new node into the chain
      node = (ADDR_CHAIN *)mMM->doMalloc(sizeof(ADDR_CHAIN));
      node->addr = info->addr;
      node->next = ent->e.chain;
      ent->e.chain = node;
      if (bVMethod) {
        entry->bNewVRetInsn = true;
        entry->nVRetInsns++;
      }
      else {
        entry->bNewDRetInsn = true;
        entry->nDRetInsns++;
      }
      chainUpdatedCHGNode(entry);
    }
  }
  return &ent->e;
}

size_t VLOOM_CHA::countNumTargets(CHGNODE *node)
{
  size_t nTotalTargets = node->nDRetInsns * node->nDRetTagts;
  size_t nVPTRs = 0, nVRetInsns = 0;
  CHGEDGE_ENTRY *itre = CHGEDGE_TREE_RB_MINMAX(&node->trDervClasses, -1);
  for (; itre != NULL; itre = CHGEDGE_TREE_RB_NEXT(itre)) {
    CHGEDGE &edge = itre->e;
    CHGNODE *child = edge.pDervNode;
    nVPTRs += child->nVtables;       // precise calculation
    nVRetInsns += child->nVRetInsns; // precise calculation
  }
  // an overapproximation
  nTotalTargets += node->nVcalls * nVPTRs + node->nVRetTagts * nVRetInsns;
  node->nPrevTargets = nTotalTargets;
  return nTotalTargets;
}

bool VLOOM_CHA::collectCHGNodes(std::set<CHGNODE *> &setAddr)
{
  CHGNODE_ENTRY *x;
  RB_FOREACH(x, CHGNODE_TREE, &mVloomCHG)
  setAddr.insert(&x->n);
  return true;
}

bool VLOOM_CHA::collectDervClasses(std::set<CHGNODE *> &setAddr, CHGNODE *node)
{
  /* collect the vptrs of derived classes */
  CHGEDGE_ENTRY *itre = CHGEDGE_TREE_RB_MINMAX(&node->trDervClasses, -1);
  for (; itre != NULL; itre = CHGEDGE_TREE_RB_NEXT(itre)) {
    CHGEDGE &edge = itre->e;
    setAddr.insert(edge.pDervNode);
  }
  return true;
}

bool VLOOM_CHA::collectVPTRs(std::set<ulong> &setAddr, CHGNODE *node)
{
  /* collect the vptrs of derived classes */
  CHGEDGE_ENTRY *itre = CHGEDGE_TREE_RB_MINMAX(&node->trDervClasses, -1);
  for (; itre != NULL; itre = CHGEDGE_TREE_RB_NEXT(itre)) {
    CHGEDGE &edge = itre->e;
    CHGNODE *child = edge.pDervNode;

    /* collect vtables */
    VTABLE_INFO *vt = child->liVtables;
    while (vt != NULL) {
      setAddr.insert((ulong)vt->addr + edge.nPtrDiff);
      vt = vt->next;
    }
  }
  return true;
}

/**
 * @brief A very different algorithm from collectDRetTagts
 *
 * @param setAddr
 * @param node
 * @param insn
 * @return true
 * @return false
 */
bool VLOOM_CHA::collectVRetTagts(std::set<ulong> &setAddr, CHGNODE *node, RETINSN_INFO *insn)
{
  uint32_t func_ID = insn->nFuncID;
  RETTAGT_ENTRY key, *ent;

  key.e.nFuncID = func_ID;
  /* collect targets from its ancestors, note that itself is one ancestor */
  for (ADDR_CHAIN *li = node->liAncestors; li != NULL; li = li->next) {
    CHGNODE *anc = (CHGNODE *)li->addr;

    // collect all thisnext targets
    ADDR_CHAIN *tchain = anc->liThisNexts;
    while (tchain != NULL) {
      setAddr.insert((ulong)tchain->addr);
      tchain = tchain->next;
    }

    // collect all next-to-vcall targets
    ent = RETTAGT_TREE_RB_FIND(&anc->trVRetTagts, &key);
    if (ent == NULL)
      continue;

    ADDR_CHAIN *chain = ent->e.chain;
    while (chain != NULL) {
      setAddr.insert((ulong)chain->addr);
      chain = chain->next;
    }
  }
  // compiler may emit codes that use direct calls to invoke virtual functions
  collectDRetTagts(setAddr, node, insn);

  return true;
}

bool VLOOM_CHA::collectDRetTagts(std::set<ulong> &setAddr, CHGNODE *node, RETINSN_INFO *insn)
{
  uint32_t func_ID = insn->nFuncID;
  /* collect targets stored by itself */
  RETTAGT_ENTRY key, *ent;

  key.e.nFuncID = func_ID;
  ent = RETTAGT_TREE_RB_FIND(&node->trDRetTagts, &key);
  if (ent == NULL)
    return false;

  ADDR_CHAIN *chain = ent->e.chain;
  while (chain != NULL) {
    setAddr.insert((ulong)chain->addr);
    chain = chain->next;
  }
  return true;
}

bool VLOOM_CHA::collectVRetInsns(std::set<RETINSN_INFO *> &setRetInsn, CHGNODE *node)
{
  RETINSN_ENTRY *x;
  RB_FOREACH(x, RETINSN_TREE, &node->trVRetInsns)
  setRetInsn.insert(&x->e);
  return true;
}

bool VLOOM_CHA::collectDRetInsns(std::set<RETINSN_INFO *> &setRetInsn, CHGNODE *node)
{
  RETINSN_ENTRY *x;
  RB_FOREACH(x, RETINSN_TREE, &node->trDRetInsns)
  setRetInsn.insert(&x->e);
  return true;
}

/****************************************************************************/
/* VLOOM VTABLE AND VPTR DETECTION                                          */
/****************************************************************************/

/****************************************************************************/
/* DYNAMIC CLASS HIERARCHY ANALYSIS                                         */
/****************************************************************************/

/* visit CHG nodes */
bool VLOOM_CHA::visitCHGNode(CHGVisitor &vtor)
{
  CHGNODE_ENTRY *x;
  RB_FOREACH(x, CHGNODE_TREE, &mVloomCHG)
  vtor.visitNode(&x->n);
  return true;
}

/* visit CHG nodes */
bool VLOOM_CHA::visitCHGDerv(CHGVisitor &vtor, CHGNODE *node)
{
  assert(node != NULL);
  CHGNODE *from = node;
  CHGEDGE_ENTRY *itre = CHGEDGE_TREE_RB_MINMAX(&from->trDervClasses, -1);
  for (; itre != NULL; itre = CHGEDGE_TREE_RB_NEXT(itre)) {
    assert(from->nDervClasses >= 1);
    CHGEDGE &edge = itre->e;
    CHGNODE *to = edge.pDervNode;
    vtor.visitDerv(from, to, &edge);
  }
  return true;
}

/* visit all nodes and edges of the graph */
bool VLOOM_CHA::visitCHGTree(CHGVisitor &vtor)
{
  for (CHGNODE_ENTRY *itrp = CHGNODE_TREE_RB_MIN(&mVloomCHG); itrp != NULL; itrp = CHGNODE_TREE_RB_NEXT(itrp)) {
    CHGNODE &from = (itrp->n);
    CHGEDGE_ENTRY *itre = CHGEDGE_TREE_RB_MINMAX(&from.trDervClasses, -1);
    if (itre == NULL) {
      assert(from.nDervClasses == 0);
      vtor.visitTree(&from, NULL, NULL);
      continue;
    }
    /* else */
    for (; itre != NULL; itre = CHGEDGE_TREE_RB_NEXT(itre)) {
      assert(from.nDervClasses >= 1);
      CHGEDGE &edge = itre->e;
      CHGNODE *to = edge.pDervNode;
      vtor.visitTree(&from, to, &edge);
    }
  }
  return true;
}

/**
 * Read in three kinds of white lists
 */
void VLOOM_CHA::readWhiteLists(void)
{
  if (mConf.pszRTenvFile != NULL)
    _readStrings(mConf.pszRTenvFile, mConf.vecRTEnv);

  if (mConf.pszFFIdvFile != NULL)
    _readDervInfo(mConf.pszFFIdvFile, mConf.mapFFIdv);

  if (mConf.pszExtraFile != NULL)
    _readDervInfo(mConf.pszExtraFile, mConf.mapExtra);
}

/**
 * For internal use
 */
bool VLOOM_CHA::_readDervInfo(const char *szFName, std::map<size_t, DERV_INFO *> &mapInfo)
{
  assert(szFName != NULL);
  char szLine[1024];
  FILE *f;

  f = fopen(szFName, "r");
  if (f == NULL)
    return false;

  while (fgets(szLine, 1024, f) != NULL) {
    /* parse line */
    char *str, *base, *derv, *szOft;
    size_t oft;

    str = utils_trimcomment(szLine);
    if (strlen(str) < 6)
      continue;

    char *p1, *p2;
    p1 = strchr(str, ';');
    p2 = strchr(p1 + 1, ';');

    if (p1 == NULL || p2 == NULL) {
      VLOOM_LOG(VLL_ERROR, "Seperate fields in %s with a semicolon ; ", szLine);
      goto ret_false;
    }

    *p2 = *p1 = '\0';
    base = utils_trimwhitespace(str);
    derv = utils_trimwhitespace(p1 + 1);
    szOft = utils_trimwhitespace(p2 + 1);

    errno = 0;
    oft = strtoul(szOft, NULL, 10);
    if (errno != 0) {
      VLOOM_LOG(VLL_ERROR, "Non-integer value in line %s?", szLine);
      goto ret_false;
    }

    size_t hashid = utils_hashstrs(base, derv);
    if (mapInfo.find(hashid) == mapInfo.end()) {
      DERV_INFO *info = new DERV_INFO(base, derv);
      info->nPtrDiff = oft;
      mapInfo[hashid] = info;
    }
  }

  fclose(f);
  return true;

ret_false:
  fclose(f);

  for (auto it : mapInfo) {
    delete it.second;
  }
  mapInfo.clear();
  return false;
}

/**
 *  read a whitelist set by runtime environment
 */
bool VLOOM_CHA::_readStrings(const char *szFName, std::vector<char *> &vecStr)
{
  assert(szFName != NULL);
  char szLine[1024];
  FILE *f;

  f = fopen(szFName, "r");
  if (f == NULL)
    return false;

  while (fgets(szLine, 1024, f) != NULL) {
    /* With comment ? */
    char *str = utils_trimcomment(szLine);

    if (strlen(str) < 2)
      continue;

    str = utils_trimwhitespace(str);
    vecStr.push_back(utils_strdup(str));
  }

  fclose(f);
  return true;
}
