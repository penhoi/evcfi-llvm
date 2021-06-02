#ifndef _HASH_FUNC_H__
#define _HASH_FUNC_H__

#include <libelf.h>

/****************************************************************************/
/* VLOOM HASH FUNCTIONS                                                     */
/****************************************************************************/
struct PatchInfo;

typedef uint32_t (*HASHFUNC)(const void *, const uint8_t *, uint64_t, uint32_t);
typedef bool (*PATCHFUNC)(PatchInfo *, const uint8_t *, uint64_t, uint32_t);

struct HPFUNCPAIR {
  const char *pName; // Hash function name.
  HASHFUNC fHash;    // Hash function.
  PATCHFUNC fPatch;  // Patch function.
  uint nRegs;        // 2 => Number of required scratch regs.
  bool bLoadBF;      // load the base address of bloom filter
  // bool b32Vtbl;      // false => VTABLE addresses must be 32bit?
  // bool bComp;        // false => Can masks be compressed?
  // uint nSize;        // 64 =>  Patch size in bytes;
};

/* Vloom hash function & patch function manager */
class VLOOM_HPFuncMgr {
private:
  class PairVisitor {
  public:
    virtual bool visit(HPFUNCPAIR *) = 0;
  };

  static HPFUNCPAIR HPPairs[];
  VLOOM_HPFuncMgr(){};
  ~VLOOM_HPFuncMgr(){};

public:
  /* Set the registers used in patches */
  static void SetRegisterSet(bool bUseR11R10R9);

  /* get the function-pair according to name */
  static HPFUNCPAIR *GetFuncPair(const char *name);

  /* Return an instance of HPFuncPairConfig */
  static HPFUNCPAIR **SetFuncPairs(uint num, char *names[]);

private:
  /* iteratorly visit mPairs */
  void visitFuncPair(PairVisitor &vtor);

  /* Prompt a correct hash function name */
  static void getFuncPrompt(const char *name);
};

#endif
