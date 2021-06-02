/**
 * @file patch.h
 * @author Pinghai (pinghaiyuan@gmail.com)
 * @brief CHGNode and Patcher is organized as a patient-doctor modle.
 * @version 0.1
 * @date 2021-01-27
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef _VLOOM_PATCHING_H__
#define _VLOOM_PATCHING_H__
#include "cha.h"
#include "config.h"
#include <libelf.h>
#include <map>

/* Manage all events about dynamic patching */

struct EnvConfig;
struct EnvRuntime;
class CHGVisitor;

struct PatchInfo {
  // const uint8_t *pInst;
  const uint8_t *bfbase;
  uint8_t *pBuf;
  uint nBytes;
  uint32_t nBFBias;
  // uint nScaleOft; // memory access with SIB mode
};

class CodePatcher {
protected:
  EnvRuntime *mConf;
  CHGNODE *mCurNode;

  /* indirect branch instruction type */
  enum INB_INSNTY {
    INSNTY_VCALL,
    INSNTY_RET,
  };

  struct InsnInfo {
    uint8_t bits : 6; // hash-table size in bit-width
    uint8_t type : 2; // instruction type
    uint8_t regs;
    uint16_t size;
    uint8_t *bfbsaddr; // base address of bloom filter
    uint8_t *codeaddr; // code point for patching
    CHGNODE *node;
    HASH_PARAM *params;
  };

public:
  CodePatcher(EnvRuntime *conf);
  virtual ~CodePatcher();
  /* The configuration should be fixed according to xxx */
  static void FixEnvRuntime(EnvRuntime *rt);
  static CodePatcher *GetPatcher(EnvRuntime *rt);

  bool patchInsns(VLOOM_CHA *cha);
  bool patchInsns(VLOOM_CHA *cha, CHGNODE *chain);
  bool _patchInsns(std::set<CHGNODE *> &setNodes, VLOOM_CHA *cha);
  void _doBatchPatching(std::map<ulong, InsnInfo *> &mapAddr2Insn);
  void _doPatching(std::set<InsnInfo *> setInsn, uint8_t *page_lo, uint8_t *page_hi);
  virtual void _patchInsn(InsnInfo *pe) = 0;

  void _checkPatchStatus(InsnInfo *pe, int nResvdRegs, int nNeedRegs, int nNopsSize);
  void _fillNopsled(uint8_t *ptr, int space);
  void _fixLastJNE(uint8_t *ptr, int space);
};

/******************************* CFIPatcher family *******************************/

// class CFICheckPatcherS : public CodePatcher {
//   uint nHashTblBits = 0;

// public:
//   CFICheckPatcherS(EnvRuntime *rt) : CodePatcher(rt) {}
//   virtual void _patchInsn(InsnInfo *pe);
// };

// class CFICheckPatcherN : public CodePatcher {
//   uint nHashTblBits = 0;

// public:
//   CFICheckPatcherN(EnvRuntime *rt) : CodePatcher(rt) {}
//   virtual void _patchInsn(InsnInfo *pe);
// };

class CFIPatcher : public CodePatcher {
protected:
  // size_t hashTblesize;
  bool mLoadBFBase = false;
  uint mHashTblBits = 0;

  CFIPatcher(EnvRuntime *rt) : CodePatcher(rt) {}

public:
  static CFIPatcher *GetCFIPatcher(EnvRuntime *rt);
  virtual void _patchInsn(InsnInfo *pe);

protected:
  bool genLoadBlmFltBase(PatchInfo &info);
  virtual bool _genLoadBlmFltBase(PatchInfo &info) { return false; }

  bool genBlmFltTest(PatchInfo &info);
  virtual bool _genBlmFltTest_loadBase(PatchInfo &info) { return false; }
  virtual bool _genBlmFltTest_codeBase(PatchInfo &info) { return false; }

  bool genRoundHashValue(PatchInfo &info) { return _genRoundHashValue(info); }
  virtual bool _genRoundHashValue(PatchInfo &info) { return false; }
};

/******************************* CounterPatcher *******************************/
class CounterPatcher : public CodePatcher {
public:
  /* mode VM_COUNT_VCALL */
  uint64_t *mCounterPage; // The memory address of counter, should < 4G.
  uint64_t *mVcallexecCounter;
  uint64_t *mRetexecCounter;

  CounterPatcher(EnvRuntime *rt);
  ~CounterPatcher();

  virtual void _patchInsn(InsnInfo *pe);
};

/******************************* CHGProfierPatcher *******************************/
class CHGProfierPatcher : public CodePatcher {
  std::map<ulong, CHGNODE *> *mapVCS2CHGNODE;
  std::map<ulong, CHGNODE *> *mapVPTR2CHGNODE;

public:
  static ulong (*mProfFunc)(ulong vcallsite, ulong vptr);

  CHGProfierPatcher(EnvRuntime *rt, void *profiler_func);
  ~CHGProfierPatcher();

  bool _patchInsns(std::set<CHGNODE *> &setNodes, VLOOM_CHA *cha);
  virtual void _patchInsn(InsnInfo *pe);

  void addVCS2CHGNODE(ulong vcallsite, CHGNODE *node);
  CHGNODE *getVCS2CHGNODE(ulong vcallsite);
  void addVPTR2CHGNODE(ulong vptr, CHGNODE *node);
  CHGNODE *getVPTR2CHGNODE(ulong vptr);
};

#endif // _VLOOM_PATCHING_H__