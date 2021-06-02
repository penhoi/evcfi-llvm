#include "patch.h"
#include "bloom.h"
#include "hash.h"
#include "logging.h"
#include "utils.h"
#include <assert.h>
#include <set>
#include <sys/mman.h>

typedef const uint8_t CUINT8;
typedef const uint CUINT;
/*****************************CodePatcher******************************************/
CodePatcher::CodePatcher(EnvRuntime *conf) : mConf(conf) {}
CodePatcher::~CodePatcher() {}

void CodePatcher::FixEnvRuntime(EnvRuntime *rt)
{
  EnvConfig *conf = rt->pEnvConf;
  if (conf == NULL)
    return;

  if (rt->arHPs == NULL) {
    rt->arHPs = VLOOM_HPFuncMgr::SetFuncPairs(conf->nHashNum, conf->arFuncName);
    rt->nHashNum = conf->nHashNum;
  }

  /* Copy configuration in order*/
  rt->bAvoidLeaking = conf->bAvoidLeaking;
  rt->bR11R10R9 = conf->bR11R10R9;

  bool bLoadBF = false;
  uint regs = 2;
  for (unsigned i = 0; i < rt->nHashNum; i++) {
    bLoadBF |= rt->arHPs[i]->bLoadBF;
    regs = VLOOM_MAXVAL(regs, rt->arHPs[i]->nRegs);
  }
  rt->bLoadBFBase = bLoadBF;
  rt->nScrthRegs = regs;

  if (rt->tRuntimeMode == VM_PROFILE_CHA) {
    rt->nHashEntBytes = 4;
    rt->nHashNum = 1; // apply one hash function is enough
    rt->bAvoidLeaking = false;
  }

  VLOOM_HPFuncMgr::SetRegisterSet(rt->bR11R10R9);
}

CodePatcher *CodePatcher::GetPatcher(EnvRuntime *rt)
{
  switch (rt->tRuntimeMode) {
  case VM_ENFORCE_VCFI:
    return CFIPatcher::GetCFIPatcher(rt);
    break;

  case VM_COUNT_INSNEXEC:
    return new CounterPatcher(rt);
    break;

  case VM_PROFILE_CHA:
    return new CHGProfierPatcher(rt, NULL);
    break;

  default:
    _UNREACHABLE;
    break;
  }
  return nullptr;
}

bool CodePatcher::patchInsns(VLOOM_CHA *cha)
{
  std::set<CHGNODE *> setNodes;
  if (!cha->collectCHGNodes(setNodes))
    return false;

  bool res = _patchInsns(setNodes, cha);
  setNodes.clear();
  return res;
}

bool CodePatcher::patchInsns(VLOOM_CHA *cha, CHGNODE *chain)
{
  std::set<CHGNODE *> setNodes;
  for (CHGNODE *node = chain; node != NULL; node = node->chain)
    setNodes.insert(node);

  bool res = _patchInsns(setNodes, cha);
  setNodes.clear();
  return res;
}

/**
 * @brief Patch the VCALLs and RETs of a chain of classes
 *
 * @param setNodes
 * @param cha
 * @return true
 * @return false
 */
bool CodePatcher::_patchInsns(std::set<CHGNODE *> &setNodes, VLOOM_CHA *cha)
{
  /* Generate bloom filter entries for each vcall-site  */
  std::map<ulong, InsnInfo *> mapInsnInfo;
  std::set<RETINSN_INFO *> setInsns;
  InsnInfo *newii, *newtmp;

  for (auto NB = setNodes.begin(), NE = setNodes.end(); NB != NE; NB++) {
    CHGNODE *node = *NB;
    BloomFilter *bf = (BloomFilter *)node->pBloomFilter;
    uint8_t *baseaddr = (uint8_t *)(bf->mCurTbl->ba); // assert(baseaddr > 0)
    uint8_t nBFbits = sizeof(size_t) * 8 - __builtin_clzl(bf->mCurTbl->sz) - 1;

    // Our LLVM-compiler doesn't generate _VPTR_Dxx_Bxx symbols if node doesn't have VTABLE.
    // It also means that this node's VCALLs and VRETs are not our protection targets.
    if (!node->bVerified)
      goto process_DRET;

    // patch VCALLs
    if (node->bNewVCall && !node->bPatchVCalls) {
      node->bPatchVCalls = true;
      for (VCALL_INFO *vci = node->liVcalls; vci != NULL; vci = vci->next) {
        newii = (InsnInfo *)malloc(sizeof(InsnInfo));
        newii->bits = nBFbits;
        newii->type = INSNTY_VCALL;
        newii->regs = vci->regs;
        newii->size = vci->size;
        newii->bfbsaddr = baseaddr;
        newii->codeaddr = vci->addr; // assert(vci->addr > vci->size)
        newii->node = node;
        newii->params = vci->params;
        mapInsnInfo.insert({(ulong)newii->codeaddr, newii});
      }
    }

    // Patch RETs of virtual functions
    if (node->bNewVRetInsn && !node->bPatchVRetInsns) {
      node->bPatchVRetInsns = true;
      setInsns.clear();
      cha->collectVRetInsns(setInsns, node);

      for (auto B = setInsns.begin(), E = setInsns.end(); B != E; B++) {
        RETINSN_INFO *ri = *B;
        newii = (InsnInfo *)malloc(sizeof(InsnInfo));
        newii->bits = nBFbits;
        newii->type = INSNTY_RET;
        newii->regs = ri->regs;
        newii->size = ri->size;
        newii->bfbsaddr = baseaddr;
        newii->node = node;
        newii->params = ri->params;

        ADDR_CHAIN *chain = ri->chain;
        assert(chain != NULL);
        newii->codeaddr = (uint8_t *)chain->addr;
        mapInsnInfo.insert({(ulong)newii->codeaddr, newii});

        chain = chain->next;
        while (chain != NULL) {
          newtmp = (InsnInfo *)malloc(sizeof(InsnInfo));
          memcpy(newtmp, newii, sizeof(InsnInfo));
          newtmp->codeaddr = (uint8_t *)chain->addr; // assert(chain->addr > ri->size)
          mapInsnInfo.insert({(ulong)newii->codeaddr, newii});
          chain = chain->next;
        }
      }
    }

  process_DRET:
    // Patch RETs of non-virtual methods
    if (node->bNewDRetInsn && !node->bPatchDRetInsns) {
      node->bPatchDRetInsns = true;
      setInsns.clear();
      cha->collectDRetInsns(setInsns, node);

      for (auto B = setInsns.begin(), E = setInsns.end(); B != E; B++) {
        RETINSN_INFO *ri = *B;
        newii = (InsnInfo *)malloc(sizeof(InsnInfo));
        newii->bits = nBFbits;
        newii->type = INSNTY_RET;
        newii->regs = ri->regs;
        newii->size = ri->size;
        newii->bfbsaddr = baseaddr;
        newii->node = node;
        newii->params = ri->params;

        ADDR_CHAIN *chain = ri->chain;
        assert(chain != NULL);
        newii->codeaddr = (uint8_t *)chain->addr;
        mapInsnInfo.insert({(ulong)newii->codeaddr, newii});

        chain = chain->next;
        while (chain != NULL) {
          newtmp = (InsnInfo *)malloc(sizeof(InsnInfo));
          memcpy(newtmp, newii, sizeof(InsnInfo));
          newtmp->codeaddr = (uint8_t *)chain->addr; // assert(chain->addr > ri->size)
          mapInsnInfo.insert({(ulong)newii->codeaddr, newii});
          chain = chain->next;
        }
      }
    }
  } // end for (auto NB xxx)

  _doBatchPatching(mapInsnInfo);

  return true;
}

/**
 * @brief For performance, patch a bunch of code points in a single mprotect
 *
 * @param mapAddr2Insn: Code points for patching: for each ele, assert(addr > size);
 */
void CodePatcher::_doBatchPatching(std::map<ulong, InsnInfo *> &mapAddr2Insn)
{
  std::set<InsnInfo *> setInsn;
  ulong lower = 0, upper = 0;

  for (auto B = mapAddr2Insn.begin(), E = mapAddr2Insn.end(); B != E; B++) {
    InsnInfo *info = B->second;
    ulong addr = (ulong)info->codeaddr;
    uint size = info->size;
    if (setInsn.size() == 0) {
      lower = ROUND_DW_PAGESZ(addr - size); // assert(addr > size);
      upper = ROUND_UP_PAGESZ(addr);
    }
    else if (addr <= upper + PAGE_SIZE) {
      upper = ROUND_UP_PAGESZ(addr);
    }
    else {
      // submit parsed code points
      _doPatching(setInsn, (uint8_t *)lower, (uint8_t *)upper);
      setInsn.clear();

      // start a new cycle
      lower = ROUND_DW_PAGESZ(addr - size);
      upper = ROUND_UP_PAGESZ(addr);
    }
    setInsn.insert(info);
  }
  // submit parsed code points
  if (setInsn.size() != 0) {
    _doPatching(setInsn, (uint8_t *)lower, (uint8_t *)upper);
  }
}

void CodePatcher::_doPatching(std::set<InsnInfo *> setInsn, uint8_t *page_lo, uint8_t *page_hi)
{
// #define DEFAULT_PERM (PROT_EXEC) # if enable XOM, make sure data/rodata sections are aligned to page boundary
#define DEFAULT_PERM (PROT_EXEC | PROT_READ)

  /* Add PROT_WRITE permission to VMA */
  if (mprotect(page_lo, page_hi - page_lo, DEFAULT_PERM | PROT_WRITE) < 0) {
#define FAIL_PROTWR "failed to set page permission for executable memory at address %p: %s"
    VLOOM_LOG(VLL_FATAL, FAIL_PROTWR, page_lo, strerror(errno));
  }

  /* patch the codes */
  for (auto B = setInsn.begin(), E = setInsn.end(); B != E; B++) {
    _patchInsn(*B);
  }

  // Revoke PROT_WRITE permission:
  if (mprotect(page_lo, page_hi - page_lo, DEFAULT_PERM) < 0) {
#define FATAL_MPROTEXE "failed to set page permission for executable memory at address %p: %s"
    VLOOM_LOG(VLL_FATAL, FATAL_MPROTEXE, page_lo, strerror(errno));
  }
}

/*
 * Patch in NOPs, layout after appliying
 * -------------------------------------
 * ptr-space: nop ...... nop
 *       ptr: original code
 * -------------------------------------
 */
void CodePatcher::_fillNopsled(uint8_t *ptr, int space)
{
  static CUINT8 nop1[] = {0x90};
  static CUINT8 nop2[] = {0x66, 0x90};
  static CUINT8 nop3[] = {0x0F, 0x1F, 0x00};
  static CUINT8 nop4[] = {0x0F, 0x1F, 0x40, 0x00};
  static CUINT8 nop5[] = {0x0F, 0x1F, 0x44, 0x00, 0x00};
  static CUINT8 nop6[] = {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00};
  static CUINT8 nop7[] = {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00};
  static CUINT8 nop8[] = {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
  static CUINT8 nop9[] = {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
  static CUINT8 nop10[] = {0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
  static CUINT8 nop11[] = {0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
  static CUINT8 *nops[] = {nop1, nop2, nop3, nop4, nop5, nop6, nop7, nop8, nop9, nop10, nop11};
  const int nops_len = sizeof(nops) / sizeof(nops[0]);

  while (space > 0) {
    int idx = (space >= nops_len ? nops_len : space);
    memcpy(ptr, nops[idx - 1], idx);
    ptr += idx;
    space -= idx;
  }
}

// fix the last JNE instruction to skip NOPs
//
void CodePatcher::_fixLastJNE(uint8_t *ptr, int space)
{
  // 0x75, 0x02,             // jnz $2
  // 0x0f, 0x0b,             // ud2
  ptr -= 4;
  uint32_t *pCode = (uint32_t *)(ptr);
  if ((*pCode == 0x0b0f0275) && (space < 250))
    ptr[1] += space;
}

void CodePatcher ::_checkPatchStatus(InsnInfo *pe, int nResvdRegs, int nNeedRegs, int nNopsSize)
{
#ifndef VLOOM_UTEST
  assert(mCurNode != NULL);
#endif
  if (nResvdRegs != nNeedRegs && mCurNode != NULL) {
    if (nResvdRegs < nNeedRegs) {
#define FATAL_LESSREGS                                                                                                \
  "failed to patch virtual call for %G%s%D; the hash function(s) require "                                            \
  "%Y%d%D scratch register%s, but only % Y % d % D % s available "
      VLOOM_LOG(VLL_FATAL, FATAL_LESSREGS, DMGNAME(mCurNode), nNeedRegs, (nNeedRegs == 1 ? "" : "s"), nResvdRegs,
                (nResvdRegs == 1 ? "is" : "are"));
    }
    else // if (nResvdRegs > nNeedRegs)
    {
#define WARN_MOREREG                                                                                                  \
  "sub-optimal instrumentation consumes %Y%u%D scratch register%s for "                                               \
  "virtual call of static type %G%s%D;  the optimal size is %Y%u%D"
      VLOOM_LOG(VLL_WARN, WARN_MOREREG, nResvdRegs, (nResvdRegs == 1 ? "" : "s"), DMGNAME(mCurNode), nNeedRegs);
    }
  }

  if (nNopsSize != 0 && mCurNode != NULL) {
    if (nNopsSize < 0) {
#define FATAL_LESSSPACE "failed to patch virtual call for %G%s%D; instrumentation padding size is %Y%u%D, need %Y%u%D"
      VLOOM_LOG(VLL_FATAL, FATAL_LESSSPACE, DMGNAME(mCurNode), pe->size, (unsigned)(pe->size - nNopsSize));
    }
    else // if (nNopsSize > 0)
    {
#define WARN_MORESPACE                                                                                                \
  "sub-optimal instrumentation padding size of %Y%u%D detected for virtual "                                          \
  "call of static type %G%s%D; the optimal size is %Y%u%D"
      VLOOM_LOG(VLL_WARN, WARN_MORESPACE, pe->size, DMGNAME(mCurNode), (unsigned)(pe->size - nNopsSize));
    }
  }
}

/******************************* CFIPatcher family *******************************/
void CFIPatcher::_patchInsn(InsnInfo *pe)
{
  uint8_t *bloom_base = pe->bfbsaddr; /* Baseaddress of the bloomfilter */
  uint8_t *pCodeAddr = pe->codeaddr;  /* Location where patch is applied */

  uint8_t szPatchBuf[256], szTmp[256];
  uint8_t *pPatchBuf = szPatchBuf;
  int nPatchBuf = 256;

  PatchInfo info;
  info.bfbase = bloom_base;
  info.pBuf = szTmp;

  int nNeedRegs = 0;

#define TRACE_PATCHVCALL "patching virtual call at location %Y%p%D"
#define TRACE_PATCHRET "patching return instruction at location %Y%p%D"
  if (pe->type == INSNTY_VCALL)
    VLOOM_LOG(VLL_TRACE, TRACE_PATCHVCALL, pCodeAddr);
  else if (pe->type == INSNTY_RET)
    VLOOM_LOG(VLL_TRACE, TRACE_PATCHRET, pCodeAddr);
  else
    _UNREACHABLE;

  mCurNode = pe->node;
  mHashTblBits = pe->bits;
  mLoadBFBase = bloom_base > (uint8_t *)0x100000000;

  /* load the base address of bloomfilter if needs */
  if ((mConf->bLoadBFBase || mLoadBFBase) && genLoadBlmFltBase(info) && nPatchBuf >= info.nBytes) {
    memcpy(pPatchBuf, info.pBuf, info.nBytes); // copy from info.pBuf
    nPatchBuf -= info.nBytes;
    pPatchBuf += info.nBytes;
    if (!mConf->bLoadBFBase)
      nNeedRegs += 1;
  }

  for (int j = 0; j < mConf->nHashNum; j++) {
    HASH_PARAM *args = &pe->params[j];
    if (mConf->arHPs[j]->fPatch(&info, bloom_base, args->n64, args->n32) && nPatchBuf >= info.nBytes) {
      memcpy(pPatchBuf, info.pBuf, info.nBytes); // copy from info.pBuf
      nPatchBuf -= info.nBytes;
      pPatchBuf += info.nBytes;

      nNeedRegs = VLOOM_MAXVAL(nNeedRegs, mConf->arHPs[j]->nRegs);
    }

    if (genRoundHashValue(info) && nPatchBuf >= info.nBytes) {
      memcpy(pPatchBuf, info.pBuf, info.nBytes); // copy from info.pBuf
      nPatchBuf -= info.nBytes;
      pPatchBuf += info.nBytes;
    }

    if (genBlmFltTest(info) && nPatchBuf >= info.nBytes) {
      memcpy(pPatchBuf, info.pBuf, info.nBytes); // copy from info.pBuf
      nPatchBuf -= info.nBytes;
      pPatchBuf += info.nBytes;
    }
  }

  int nNopsSize = pe->size - (pPatchBuf - szPatchBuf); /* NOP size needed be patched */
  int nResvdRegs = pe->regs;                           /* Number of reserved registers */

  _checkPatchStatus(pe, nResvdRegs, nNeedRegs, nNopsSize);
  if (nNopsSize > 0) {
    _fillNopsled(pPatchBuf, nNopsSize);
    _fixLastJNE(pPatchBuf, nNopsSize); // fix the last JNE instruction to skip nops
  }

  // patch to code region
  memcpy(pCodeAddr - pe->size, szPatchBuf, pe->size);
}

bool CFIPatcher::genLoadBlmFltBase(PatchInfo &info)
{
  if (mConf->bLoadBFBase || mLoadBFBase)
    return _genLoadBlmFltBase(info);
  else
    return false;
}

bool CFIPatcher::genBlmFltTest(PatchInfo &info)
{
  if (mLoadBFBase)
    return _genBlmFltTest_loadBase(info);
  else
    return _genBlmFltTest_codeBase(info);
}

class CFIPatcher_GPRS : public CFIPatcher {
  friend CFIPatcher;

protected:
  CFIPatcher_GPRS(EnvRuntime *rt) : CFIPatcher(rt) {}

public:
  virtual bool _genLoadBlmFltBase(PatchInfo &info);

  virtual bool _genBlmFltTest_loadBase(PatchInfo &info);
  virtual bool _genBlmFltTest_codeBase(PatchInfo &info);

  virtual bool _genRoundHashValue(PatchInfo &info);
};

// class CFICodeBloomBase_GPRS : public CFIPatcher_GPRS {
//   friend CFIPatcher;
//   CFICodeBloomBase_GPRS(EnvRuntime *rt) : CFIPatcher_GPRS(rt) {}

// public:
//   virtual bool genBlmFltTest(PatchInfo &info);
//   virtual bool genLoadBlmFltBase(PatchInfo &info);
// };

class CFIPatcher_GPRN : public CFIPatcher {
  friend CFIPatcher;

protected:
  CFIPatcher_GPRN(EnvRuntime *rt) : CFIPatcher(rt) {}

public:
  virtual bool _genLoadBlmFltBase(PatchInfo &info);

  virtual bool _genBlmFltTest_loadBase(PatchInfo &info);
  virtual bool _genBlmFltTest_codeBase(PatchInfo &info);

  virtual bool _genRoundHashValue(PatchInfo &info);
};

// 48 ba 78 56 34 12 00 00 00 00   movabs $0x12345678,%rdx
bool CFIPatcher_GPRS::_genLoadBlmFltBase(PatchInfo &info)
{
  // Load Bloom base
  static CUINT8 movabsInst[] = {0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static CUINT movabsInst_len = sizeof(movabsInst);

  uint8_t *ptr = info.pBuf;
  memcpy(ptr, movabsInst, movabsInst_len);
  memcpy(ptr + 2, (char *)&info.bfbase, 8);
  info.nBytes = movabsInst_len;

  return true;
}

// 0:	f6 04 0a ff          	testb  $0xff,(%rdx,%rcx,1)
// 4:	f6 04 4a ff          	testb  $0xff,(%rdx,%rcx,2)
// 8:	f6 04 8a ff          	testb  $0xff,(%rdx,%rcx,4)
bool CFIPatcher_GPRS::_genBlmFltTest_loadBase(PatchInfo &info)
{
  static CUINT8 testbSIB[] = {0x0a, 0x0a, 0x4a, 0x0a, 0x8a};
  static CUINT8 testInst[] = {
      0xf6, 0x04, 0x0a, 0xff, // testb  $0xff,(%rdx,%rcx,1)
      0x75, 0x02,             // jnz $2                       #Entry non-zero?
      0x0f, 0x0b,             // ud2                          #Invalid vptr
  };
  static CUINT testInst_len = sizeof(testInst);

  uint8_t *ptr = info.pBuf;
  memcpy(ptr, testInst, testInst_len);
  ptr[2] = testbSIB[mConf->nHashEntBytes];
  info.nBytes = testInst_len;

  return true;
}

// 8:  49 c1 e1 02                 shl    $0x2,%rcx
// 0:  f6 81 78 56 34 12 ff        testb  $0xff,0x12345678(%rcx)
bool CFIPatcher_GPRS::_genBlmFltTest_codeBase(PatchInfo &info)
{
  static CUINT8 shiftInst[] = {0x49, 0xc1, 0xe1, 0x02};
  static CUINT shiftInst_len = sizeof(shiftInst);
  static CUINT8 shift_cnt[] = {0, 0, 1, 0, 2};

  static CUINT8 testInst[] = {
      0xf6, 0x81, 0x78, 0x56, 0x34, 0x12, 0xff, // testb  $0xff,0x12345678(%rcx)
      0x75, 0x02,                               // jnz $2  #Entry non-zero?
      0x0f, 0x0b,                               // ud2     #Invalid vptr
  };
  static CUINT testInst_len = sizeof(testInst);

  uint8_t *ptr = info.pBuf;
  int idx = mConf->nHashEntBytes;
  uint nBytes = 0;

  if (idx > 1) {
    memcpy(ptr, shiftInst, shiftInst_len);
    ptr[3] = shift_cnt[idx];
    ptr += shiftInst_len;
    nBytes += shiftInst_len;
  }
  memcpy(ptr, testInst, testInst_len);
  memcpy(ptr + 2, (char *)&info.bfbase, 4);
  nBytes += testInst_len;
  info.nBytes = nBytes;

  return true;
}

// 0:	0f b6 c9             	movzbl %cl,%ecx
// 3:	0f b7 c9             	movzwl %cx,%ecx
// 6:	81 e1 78 56 34 12    	and    $0x12345678,%ecx
bool CFIPatcher_GPRS::_genRoundHashValue(PatchInfo &info)
{
  static CUINT8 movzbInst[] = {0x0F, 0xB6, 0xC9};
  static CUINT8 movzwInst[] = {0x0F, 0xB7, 0xC9};
  static CUINT8 andwInst[] = {0x81, 0xE1, 0x00, 0x00, 0x00, 0x00};
  static CUINT movzbInst_len = sizeof(movzbInst);
  static CUINT movzwInst_len = sizeof(movzwInst);
  static CUINT andwInst_len = sizeof(andwInst);

  uint8_t *ptr = info.pBuf;
  if (mHashTblBits == 8) {
    memcpy(ptr, movzbInst, movzbInst_len);
    info.nBytes = movzbInst_len;
    return true;
  }
  else if (mHashTblBits == 16) {
    memcpy(ptr, movzwInst, movzbInst_len);
    info.nBytes = movzwInst_len;
    return true;
  }
  else if (mHashTblBits < 32) {
    uint32_t mask = (1 << mHashTblBits) - 1;
    memcpy(ptr, andwInst, movzbInst_len);
    memcpy(ptr + 2, &mask, 4);
    info.nBytes = andwInst_len;
    return true;
  }
  else
    return false;
}

// 0:	49 ba 78 56 34 12 00 00 00 00  movabs $0x12345678,%r10
bool CFIPatcher_GPRN::_genLoadBlmFltBase(PatchInfo &info)
{
  // Load Bloom base
  static CUINT8 movabsInst[] = {0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static CUINT movabsInst_len = sizeof(movabsInst);

  uint8_t *ptr = info.pBuf;
  memcpy(ptr, movabsInst, movabsInst_len);
  memcpy(ptr + 2, (char *)&info.bfbase, 8);
  info.nBytes = movabsInst_len;

  return true;
}

// 0:  43 f6 04 1a ff    testb  $0xff,(%r10,%r11,1)
// 5:  43 f6 04 5a ff    testb  $0xff,(%r10,%r11,2)
// a:  43 f6 04 9a ff    testb  $0xff,(%r10,%r11,4)
bool CFIPatcher_GPRN::_genBlmFltTest_loadBase(PatchInfo &info)
{
  static CUINT8 testbSIB[] = {0x1a, 0x1a, 0x5a, 0x0a, 0x9a};
  static CUINT8 testInst[] = {
      0x43, 0xf6, 0x04, 0x1a, 0xff, // testb  $0xff,(%r10,%r11,1)
      0x75, 0x02,                   // jnz $2    #Entry non-zero?
      0x0f, 0x0b,                   // ud2       #Invalid vptr
  };
  static CUINT testInst_len = sizeof(testInst);

  uint8_t *ptr = info.pBuf;
  memcpy(ptr, testInst, testInst_len);
  ptr[3] = testbSIB[mConf->nHashEntBytes];
  info.nBytes = testInst_len;

  return true;
}

// 8:  49 c1 e3 02                 shl    $0x2,%r11
// 0:  41 f6 83 78 56 34 12 ff     testb  $0xff,0x12345678(%r11)
bool CFIPatcher_GPRN ::_genBlmFltTest_codeBase(PatchInfo &info)
{
  static CUINT8 shiftInst[] = {0x49, 0xc1, 0xe3, 0x02};
  static CUINT shiftInst_len = sizeof(shiftInst);
  static CUINT8 shift_cnt[] = {0, 0, 1, 0, 2};

  static CUINT8 testInst[] = {
      0x41, 0xf6, 0x83, 0x78, 0x56, 0x34, 0x12, 0xff, // testb  $0xff,0x12345678 (%r10,1)
      0x75, 0x02,                                     // jnz $2                       #Entry non-zero?
      0x0f, 0x0b,                                     // ud2                          #Invalid vptr
  };
  static CUINT testInst_len = sizeof(testInst);

  uint8_t *ptr = info.pBuf;
  int idx = mConf->nHashEntBytes;
  uint nBytes = 0;

  if (idx > 1) {
    memcpy(ptr, shiftInst, shiftInst_len);
    ptr[3] = shift_cnt[idx];
    ptr += shiftInst_len;
    nBytes += shiftInst_len;
  }
  memcpy(ptr, testInst, testInst_len);
  memcpy(ptr + 3, (char *)&info.bfbase, 4);
  nBytes += testInst_len;
  info.nBytes = nBytes;

  return true;
}

// 0:  45 0f b6 db           movzbl %r11b,%r11d
// 4:  45 0f b7 db           movzwl %r11w,%r11d
// 8:  41 81 e3 78 56 34 12  and    $0x12345678,%r11d
bool CFIPatcher_GPRN::_genRoundHashValue(PatchInfo &info)
{
  static CUINT8 movzbInst[] = {0x45, 0x0F, 0xB6, 0xDB};
  static CUINT8 movzwInst[] = {0x45, 0x0F, 0xB7, 0xDB};
  static CUINT8 andwInst[] = {0x41, 0x81, 0xE3, 0x00, 0x00, 0x00, 0x00};
  static CUINT movzbInst_len = sizeof(movzbInst);
  static CUINT movzwInst_len = sizeof(movzwInst);
  static CUINT andwInst_len = sizeof(andwInst);

  uint8_t *ptr = info.pBuf;
  if (mHashTblBits == 8) {
    memcpy(ptr, movzbInst, movzbInst_len);
    info.nBytes = movzbInst_len;
    return true;
  }
  else if (mHashTblBits == 16) {
    memcpy(ptr, movzwInst, movzbInst_len);
    info.nBytes = movzwInst_len;
    return true;
  }
  else if (mHashTblBits < 32) {
    uint32_t mask = (1 << mHashTblBits) - 1;
    memcpy(ptr, andwInst, movzbInst_len);
    memcpy(ptr + 3, &mask, 4);
    info.nBytes = andwInst_len;
    return true;
  }
  else
    return false;
}

CFIPatcher *CFIPatcher::GetCFIPatcher(EnvRuntime *rt)
{
  if (rt->bR11R10R9)
    return new CFIPatcher_GPRN(rt);
  else
    return new CFIPatcher_GPRS(rt);
}

/*****************************CounterPatcher**************************************/
CounterPatcher::CounterPatcher(EnvRuntime *rt) : CodePatcher(rt)
{
#define MAP_FLAGS (MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT)

  /* Be consistent with patcher, should put in Low 4Gb address space */
  mCounterPage = (uint64_t *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_FLAGS, -1, 0);
  mVcallexecCounter = &mCounterPage[0];
  mRetexecCounter = &mCounterPage[1];
}

CounterPatcher::~CounterPatcher()
{
  /* report the results */
  VLOOM_LOG(VLL_RESULT, "Execution frequency of VCALLs is: %lu in total\n", *mVcallexecCounter);
  VLOOM_LOG(VLL_RESULT, "Execution frequency of RETs is: %lu in total\n", *mRetexecCounter);

  munmap(mCounterPage, 0x1000);
}

// global counter
void CounterPatcher::_patchInsn(InsnInfo *pe)
{
  /* lock inc [mem]*/
  static CUINT8 szLockinc[] = {0xF0, 0x48, 0xFF, 0x04, 0x25, 0x00, 0x00, 0x01, 0x00};
  static CUINT nLockinc = sizeof(szLockinc);
  static CUINT nConstOft = 5;

  uint8_t *pCodeAddr = (uint8_t *)pe->codeaddr; /* Location where patch is applied */
  int nNopsSize = pe->size;                     /* NOP size needed be patched */
  uint8_t *pCounter;

#define TRACE_PATCHVCALL_CNT "patching virtual call at location %Y%p%D with a counter"
#define TRACE_PATCHRET_CNT "patching return instruction at location %Y%p%D with a counter"
  if (pe->type == INSNTY_VCALL)
    VLOOM_LOG(VLL_TRACE, TRACE_PATCHVCALL_CNT, pCodeAddr);
  else if (pe->type == INSNTY_RET)
    VLOOM_LOG(VLL_TRACE, TRACE_PATCHRET_CNT, pCodeAddr);
  else
    _UNREACHABLE;

  pCodeAddr -= nLockinc;
  nNopsSize -= nLockinc;
  switch (pe->type) {
  case INSNTY_VCALL:
    pCounter = (uint8_t *)mVcallexecCounter;
    break;
  case INSNTY_RET:
    pCounter = (uint8_t *)mRetexecCounter;
    break;
  default:
    _UNREACHABLE;
    break;
  }

  if (nNopsSize >= 0) {
    memcpy(pCodeAddr, szLockinc, nLockinc);
    memcpy(pCodeAddr + nConstOft, pCounter, 4); // only works for little edian
    _fillNopsled(pCodeAddr, nNopsSize);
  }
  else {
#define FATAL_NOSPACE "failed to patch virtual call for %G%s%D; instrumentation padding size is %Y%u%D, need %Y%u%D"
    VLOOM_LOG(VLL_FATAL, FATAL_NOSPACE, DMGNAME(mCurNode), pe->size, (unsigned)(pe->size - nNopsSize));
  }
}

/*****************************CHGProfierPatcher**************************************/

ulong (*CHGProfierPatcher::mProfFunc)(ulong vcallsite, ulong vptr) = NULL;

CHGProfierPatcher::CHGProfierPatcher(EnvRuntime *rt, void *profiler_func) : CodePatcher(rt)
{
  mProfFunc = (ulong(*)(ulong vcallsite, ulong vptr))profiler_func;

  mapVCS2CHGNODE = new std::map<ulong, CHGNODE *>();
  mapVPTR2CHGNODE = new std::map<ulong, CHGNODE *>();

  // for (VTABLE_INFO *vtbl = dervNode->liVtables; vtbl != NULL; vtbl = vtbl->next)
  //   AddVPTR2CHGNODE((ulong)vtbl->addr + e.nPtrDiff, dervNode);

  // AddVCS2CHGNODE((ulong)patch->addr, entry);

  // AddVCS2CHGNODE((ulong)patch->addr, entry);
  // AddVCS2CHGNODE((ulong)patch->addr, entry);
}

CHGProfierPatcher::~CHGProfierPatcher()
{
  if (mapVCS2CHGNODE != NULL)
    delete mapVCS2CHGNODE;

  if (mapVPTR2CHGNODE != NULL)
    delete mapVPTR2CHGNODE;
}

void CHGProfierPatcher::addVCS2CHGNODE(ulong vcallsite, CHGNODE *node) { mapVCS2CHGNODE->insert({vcallsite, node}); }

CHGNODE *CHGProfierPatcher::getVCS2CHGNODE(ulong vcallsite)
{
  auto ent = mapVCS2CHGNODE->find(vcallsite);
  return ent->second;
}

void CHGProfierPatcher::addVPTR2CHGNODE(ulong vptr, CHGNODE *node) { mapVPTR2CHGNODE->insert({vptr, node}); }

CHGNODE *CHGProfierPatcher::getVPTR2CHGNODE(ulong vptr)
{
  auto ent = mapVPTR2CHGNODE->find(vptr);
  return ent->second;
}

// ulong vloom_profiler_whitelist(ulong vcallsite, ulong vptr)
// {
//   // static & dynamic type
//   auto stype = mapVCS2CHGNODE->find(vcallsite);
//   auto dtype = mapVPTR2CHGNODE->find(vptr);
//   CHGNODE *base = stype->second;
//   CHGNODE *derv = dtype->second;

//   if (base == NULL || derv == NULL) {
//     printf("Some are null\n");
//   }
//   else {
//     printf("Both are not null %s:%s\n", RAWNAME(base), RAWNAME(derv));
//   }

//   return vptr;
// }

extern "C" ulong vloom_profiler(ulong vcallsite, ulong vptr)
{
  // printf("%s\n", __FUNCTION__);
  return CHGProfierPatcher::mProfFunc(vcallsite, vptr);
}

asm(".text\n\t"
    ".align 4\n\t"
    ".local profiler_stub\n\t"
    "profiler_stub:\n\t"
    // "_xsaveall:\n\t"
    "push %rbp\n\t"
    "mov %rsp, %rbp\n\t"
    "sub $8*20, %rsp\n\t"
    "mov %rdi, 8*1(%rsp)\n\t"
    "mov %rsi, 8*2(%rsp)\n\t"
    "mov %rdx, 8*3(%rsp)\n\t"
    "mov %rcx, 8*4(%rsp)\n\t"
    "mov %rbx, 8*5(%rsp)\n\t"
    "mov %r8, 8*8(%rsp)\n\t"
    "mov %r9, 8*9(%rsp)\n\t"
    "mov %r10, 8*10(%rsp)\n\t"
    "mov %r11, 8*11(%rsp)\n\t"
    "mov %r12, 8*12(%rsp)\n\t"
    "mov %r13, 8*13(%rsp)\n\t"
    "mov %r14, 8*14(%rsp)\n\t"
    "mov %r15, 8*15(%rsp)\n\t"
    // "mov %rsi, %rax\n\t"
    "call vloom_profiler\n\t"
    // "_xrestoreall:\n\t"
    "mov 8*1(%rsp),%rdi\n\t"
    "mov 8*2(%rsp),%rsi\n\t"
    "mov 8*3(%rsp),%rdx\n\t"
    "mov 8*4(%rsp),%rcx\n\t"
    "mov 8*5(%rsp),%rbx\n\t"
    "mov 8*8(%rsp),%r8\n\t"
    "mov 8*9(%rsp),%r9\n\t"
    "mov 8*10(%rsp),%r10\n\t"
    "mov 8*11(%rsp),%r11\n\t"
    "mov 8*12(%rsp),%r12\n\t"
    "mov 8*13(%rsp),%r13\n\t"
    "mov 8*14(%rsp),%r14\n\t"
    "mov 8*15(%rsp),%r15\n\t"
    "mov %rbp, %rsp\n\t"
    "pop %rbp\n\t"
    "ret\n\t");
extern "C" long profiler_stub(long, long);

/* instrument a hook to profile at give call-site */
void CHGProfierPatcher::_patchInsn(InsnInfo *pe)
{
  uint8_t *pCodeAddr = (uint8_t *)pe->codeaddr; /* Location where patch is applied */
  int nNopsSize = pe->size;                     /* NOP size needed be patched */

  const uint8_t szHookStub[] = {
      0x57,                                                       // push %rdi
      0x56,                                                       // push %rsi
      0x48, 0x89, 0xc6,                                           // mov    %rax,%rsi
      0x48, 0x8D, 0x3D, 0x0e, 0x00, 0x00, 0x00,                   // lea    0xe(%rip),%rdi
      0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs $profiler_stub,%rax
      0xff, 0xd0,                                                 // callq  *%rax
      0x5e,                                                       // pop %rsi
      0x5f,                                                       // pop %rdi
  };

  static CUINT nHookStub = sizeof(szHookStub);
  static CUINT nConstOft = 14;

#define TRACE_PATCHVCALL_PROF "patching virtual call at location %Y%p%D with a profiler"
#define TRACE_PATCHRET_PROF "patching return instruction at location %Y%p%D with a profiler"
  if (pe->type == INSNTY_VCALL)
    VLOOM_LOG(VLL_TRACE, TRACE_PATCHVCALL_PROF, pCodeAddr);
  else if (pe->type == INSNTY_RET)
    VLOOM_LOG(VLL_TRACE, TRACE_PATCHRET_PROF, pCodeAddr);
  else
    _UNREACHABLE;

  pCodeAddr -= nHookStub;
  nNopsSize -= nHookStub;
  if (nNopsSize >= 0) {
    memcpy(pCodeAddr, szHookStub, nHookStub);
    *(long *)(pCodeAddr + nConstOft) = (long)profiler_stub;
    _fillNopsled(pCodeAddr, nNopsSize);
  }
  else {
#define FATAL_PNOSPACE "failed to patch virtual call for %G%s%D; instrumentation padding size is %Y%u%D, need %Y%u%D"
    VLOOM_LOG(VLL_FATAL, FATAL_PNOSPACE, DMGNAME(mCurNode), pe->size, (unsigned)(pe->size - nNopsSize));
  }
}

bool CHGProfierPatcher::_patchInsns(std::set<CHGNODE *> &setNodes, VLOOM_CHA *cha)
{
  return CodePatcher::_patchInsns(setNodes, cha);
}

#ifdef REVERSE
/* All these stuff are used for debugging purpose */
struct VLOOM_CHGCAST {
  RB_ENTRY(VLOOM_CHGCAST)
  entry;
  CHGNODE *asIS;

  static int compare(const VLOOM_CHGCAST *a, const VLOOM_CHGCAST *b)
  {
    if (a->asIS == b->asIS)
      return 0;
    else
      return (a->asIS < b->asIS ? -1 : 1);
  }
};

RB_HEAD(VLOOM_UPCAST, VLOOM_CHGCAST);
RB_GENERATE(VLOOM_UPCAST, VLOOM_CHGCAST, entry, VLOOM_CHGCAST::compare);

struct VLOOM_CHGMAP_VPTR2NODE {
  RB_ENTRY(VLOOM_CHGMAP_VPTR2NODE)
  entry;

  const void *vptr;   // The vptr, the key of RB-tree;
  CHGNODE *mytype;    // The real type of current object;
  uint32_t num_isAS;  // Total number of AS-IS types;
  VLOOM_UPCAST allAS; // The used-as type of current object;

  static int compare(const VLOOM_CHGMAP_VPTR2NODE *a, const VLOOM_CHGMAP_VPTR2NODE *b)
  {
    ulong pa = (ulong)a->vptr;
    ulong pb = (ulong)b->vptr;

    if (pa == pb)
      return 0;
    else
      return (pa < pb) ? -1 : 1;
  }
};

/* class hierachy graph: mapping from vptr to node */
RB_HEAD(VLOOM_CHGMAP, VLOOM_CHGMAP_VPTR2NODE);
RB_GENERATE(VLOOM_CHGMAP, VLOOM_CHGMAP_VPTR2NODE, entry, VLOOM_CHGMAP_VPTR2NODE::compare);

static VLOOM_CHGMAP vloom_chgmap = RB_INITIALIZER(&vloom_chgmap);
#endif // REVERSE

#ifdef REVERSE

/*
 * Looking up a VLOOM_CHGMAP_VPTR2NODE node, insert if does not exist;
 */
static VLOOM_CHGMAP_VPTR2NODE *_vloom_cha_chgmap_insert_upcast(VLOOM_CHGMAP *chgmap, const void *vptr, CHGNODE *myType,
                                                               CHGNODE *asIS)
{
  VLOOM_CHGMAP_VPTR2NODE *mapent; /* data entry in the CHGMAP */
  VLOOM_CHGMAP_VPTR2NODE mapkey;

  mapkey.vptr = vptr;
  mapent = VLOOM_CHGMAP_RB_FIND(chgmap, &mapkey);
  if (mapent == NULL) { /* create entry */
    mapent = (VLOOM_CHGMAP_VPTR2NODE *)mMM->doMalloc(sizeof(VLOOM_CHGMAP_VPTR2NODE));
    memset(mapent, 0, sizeof(VLOOM_CHGMAP_VPTR2NODE));
    mapent->vptr = vptr;
    mapent->mytype = myType;
    mapent->allAS = RB_INITIALIZER(&mapent->allAS);
    VLOOM_CHGMAP_RB_INSERT(chgmap, mapent);
  }

  VLOOM_CHGCAST *castent;
  VLOOM_CHGCAST castkey;
  castkey.asIS = asIS;

  castent = VLOOM_UPCAST_RB_FIND(&mapent->allAS, &castkey);
  if (castent == NULL) { /* create new entry */
    castent = (VLOOM_CHGCAST *)mMM->doMalloc(sizeof(VLOOM_CHGCAST));
    castent->asIS = asIS;
    VLOOM_UPCAST_RB_INSERT(&mapent->allAS, castent);
  }

  (mapent->num_isAS)++;

  return mapent;
}

/* creat VLOOM_CHGMAP_VPTR2NODE */
VLOOM_UTEST void vloom_cha_chgmap_insert(void *data, CHGNODE *pnode, CHGEDGE *edge, CHGNODE *dnode)
{
  VLOOM_CHGMAP *chgmap = (VLOOM_CHGMAP *)data;
  VLOOM_CHGMAP_VPTR2NODE *mapent; /* data entry in the CHGMAP */
  VLOOM_CHGMAP_VPTR2NODE mapkey;

  if (dnode == NULL) {
    assert(pnode != NULL);
    void *vptr = pnode->vtable.orign;

    _vloom_cha_chgmap_insert_upcast(chgmap, vptr, pnode, pnode);

    /* mutliple VTABLEs for a sigle class */
    if (pnode->next_vtable == NULL)
      return;

    /* Iterate each VTABLE */
    for (int i = 0; i < VLOOM_VTALBE_MAXMAPPING; i++) {
      vptr = pnode->next_vtable[i].orign;
      if (vptr == NULL) // No more VTABLE
        break;

      _vloom_cha_chgmap_insert_upcast(chgmap, vptr, pnode, pnode);
    }
  }
  else { /* dnode != NULL */
    void *vptr = (void *)((ulong)dnode->vtable.orign + edge->offset);

    _vloom_cha_chgmap_insert_upcast(chgmap, vptr, dnode, pnode);

    /* if dnode has multiple VTABLEs to a single class name */
    if (dnode->next_vtable == NULL)
      return;

    /* Iterate each VTABLE */
    for (int i = 0; i < VLOOM_VTALBE_MAXMAPPING; i++) {
      void *vptr = (void *)((ulong)dnode->next_vtable[i].orign + edge->offset);
      if (vptr == NULL) // No more VTABLE
        break;

      _vloom_cha_chgmap_insert_upcast(chgmap, vptr, dnode, pnode);
    }
  }
}

/*
 * Lookup (or create) an entry in the VLOOM table.
 */
long white_list_null[] = {
    // 0x7ffff79a57b0, //std::ctype<char>0x7ffff79a57b0, 0x7ffff79a57a0
    0,
};

long white_list_skip[] = {
    0x7fffa86957f8, // 0x7fffa86a3a88, //<vtable for nsXPTCStubBase+16>
    0,
};

VLOOM_UTEST void *vloom_cha_chgmap_enquire(VLOOM_CHGMAP *chgmap, void *vtable_pointer)
{
  VLOOM_CHGMAP_VPTR2NODE key;
  ulong vptr = (ulong)vtable_pointer;
  key.vptr = vtable_pointer;

  VLOOM_CHGMAP_VPTR2NODE *entry = VLOOM_CHGMAP_RB_FIND(chgmap, &key);
  if (entry == NULL) {
    for (long *ptr = white_list_null; *ptr != 0; ptr++) {
      if ((vptr & 0xfff) == (*ptr & 0xfff))
        return NULL;
    }
    // asm("int3");
    VLOOM_LOG(VLL_VCFIBUG, "Cannot find entry for %lx", vptr);
  }
  else {
    for (long *ptr = white_list_skip; *ptr != 0; ptr++) {
      if ((vptr & 0xfff) == (*ptr & 0xfff))
        return NULL;
    }
    // asm("int3");

    CHGNODE *self = entry->mytype;
    for (VLOOM_CHGCAST *itas = VLOOM_UPCAST_RB_MINMAX(&entry->allAS, -1); itas != NULL;
         itas = VLOOM_UPCAST_RB_NEXT(itas)) {
      CHGNODE *as = itas->asIS;

      VLOOM_LOG(VLL_VCFIBUG, "Type %s used-as Type %s", self->pszVtableKeyName, as->pszVtableKeyName);
      // printf("Type %s used-as Type %s\n", self->pszVtableKeyName,
      // as->pszVtableKeyName);
    }
  }
  return entry;
}

void *vloom_cha_chgmap_enquire_wrapper(void *vtable_pointer)
{
  VLOOM_CHGMAP *chgmap = &vloom_chgmap;
  return vloom_cha_chgmap_enquire(chgmap, vtable_pointer);
}

#endif // REVERSE