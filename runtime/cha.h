#ifndef _VLOOM_CHA_H__
#define _VLOOM_CHA_H__
#include <map>
#include <set>
#include <vector>

#include "tree.h"
#include <libelf.h>
#include <string.h>

/* Used for setting salt-values */
struct HASH_PARAM {
  uint64_t n64; // 64bit hash parameter
  uint32_t n32; // 32bit hash parameter
  // uint32_t nOfset : 30; // offset to bitmap
  // uint32_t nIndex : 2;  // which bitmap?
};

/* Meta-data of a vtable */
struct VTABLE_INFO {
  uint16_t size; // table size in bytes
  void *addr;    // VTABLE location
  VTABLE_INFO *next;
};

/* Each vcall-site would be patched, this structure stores the details */
struct VCALL_INFO {
  uint8_t regs;
  uint16_t size;
  uint8_t *addr;
  VCALL_INFO *next;
  HASH_PARAM params[]; // Each vcall-site has its own randomized ID
};

/* A simple value chain */
struct ADDR_CHAIN {
  void *addr;
  ADDR_CHAIN *next;
};

/* Each RET instruction of class methods would be patched */
struct RETINSN_INFO {
  union {
    uint64_t nMethodID;
    struct {
      uint32_t nClassID;
      uint32_t nFuncID;
    };
  };

  /* A chain of addresses */
  union {
    uint8_t *addr;     // used to store a single address
    ADDR_CHAIN *chain; // used to link an address chain
  };

  /* information get from by parsing Typed-symbols */
  uint8_t args;
  uint8_t regs;
  uint16_t size;

  // Each RET-instruction has its own randomized ID
  HASH_PARAM params[];
};
/* Ret instruction information */
struct RETINSN_ENTRY {
  RB_ENTRY(RETINSN_ENTRY) entry;
  RETINSN_INFO e;

  static int compare(const RETINSN_ENTRY *ae, const RETINSN_ENTRY *be)
  {
    const RETINSN_INFO &a = ae->e;
    const RETINSN_INFO &b = be->e;
    if (a.nFuncID == b.nFuncID)
      return 0;
    else
      return (a.nFuncID < b.nFuncID) ? -1 : 1;
  }
};
RB_HEAD(RETINSN_TREE, RETINSN_ENTRY);

/* Information about a return target, a code point next to a call-site */
struct RETTAGT_INFO {
  union {
    uint64_t nMethodID;
    struct {
      uint32_t nClassID, nFuncID;
    };
  };

  /* A chain of addresses */
  union {
    uint8_t *addr;     // used to store a single address
    ADDR_CHAIN *chain; // used to link an address chain
  };
};
/* Ret target information */
struct RETTAGT_ENTRY {
  RB_ENTRY(RETTAGT_ENTRY) entry;
  RETTAGT_INFO e;
  static int compare(const RETTAGT_ENTRY *ae, const RETTAGT_ENTRY *be)
  {
    const RETTAGT_INFO &a = ae->e;
    const RETTAGT_INFO &b = be->e;
    if (a.nFuncID == b.nFuncID)
      return 0;
    else
      return (a.nFuncID < b.nFuncID) ? -1 : 1;
  }
};
RB_HEAD(RETTAGT_TREE, RETTAGT_ENTRY);

/* This stucture stores the derivation relationship */
struct CHGNODE;
struct CHGEDGE {
  CHGNODE *pBaseNode;
  CHGNODE *pDervNode;
  size_t nPtrDiff;
};
struct CHGEDGE_ENTRY {
  RB_ENTRY(CHGEDGE_ENTRY) entry;
  CHGEDGE e;

  static int compare(const CHGEDGE_ENTRY *ae, const CHGEDGE_ENTRY *be)
  {
    const CHGEDGE &a = ae->e;
    const CHGEDGE &b = be->e;
    if (a.pDervNode != b.pDervNode)
      return (a.pDervNode < b.pDervNode) ? -1 : 1;

    if (a.nPtrDiff == b.nPtrDiff)
      return 0;
    else
      return (a.nPtrDiff < b.nPtrDiff) ? -1 : 1;
  }
};
RB_HEAD(CHGEDGE_TREE, CHGEDGE_ENTRY);

struct CHGNODE {
  uint32_t nClassID; // hash(vtable_Name)
  bool bVerified;    // created by parsing __VLOOM_VPTR symbol

  /* status information of this node. */
  union {
    uint16_t nStatus; // fix-me: assume size(uint) == size(bool) * 4
    struct {
      uint16_t bNewVtable : 1;   // has new vtable
      uint16_t bNewVCall : 1;    // has new vcall-site
      uint16_t bNewDervCls : 1;  // has new derived classes
      uint16_t bNewAncestor : 1; // has a new ancestor
      uint16_t bNewVRetInsn : 1; // Added new RET instruction
      uint16_t bNewVRetTagt : 1; // Added new return target
      uint16_t bNewDRetInsn : 1; // Added new RET instruction
      uint16_t bNewDRetTagt : 1; // Added new return target
      uint16_t bNewThisNext : 1; // Here would be a target of all VRETs

      uint16_t bUpdtBF4Dervs : 1;  // updated BF for new Derv relationship
      uint16_t bUpdtBF4VTagts : 1; // updated BF for VRET targets
      uint16_t bUpdtBF4DTagts : 1; // updated BF for DRET targets

      uint16_t bPatchVCalls : 1;    // patched vcalls
      uint16_t bPatchVRetInsns : 1; // patched VRetInsns
      uint16_t bPatchDRetInsns : 1; // patched DRetInsns

      uint16_t bChained : 1; // chained into *chain*
    };
  };

  // A bloom-filter to accommodate all its targets
  void *pBloomFilter;

  /* some statistical information about Bloom-filter entries */
  uint32_t nPrevTargets; // The number of all possible targets

  /* Several vtables may have the same class name */
  int nVtables;
  VTABLE_INFO *liVtables;

  /* Each vcall-site has a patch entry */
  int nVcalls;
  VCALL_INFO *liVcalls;

  /* RET instructions of methods of this class, organized as a tree for quick searching */
  int nVRetInsns;
  RETINSN_TREE trVRetInsns;
  int nDRetInsns;
  RETINSN_TREE trDRetInsns;

  /* Return targets of methods of this class, organized as a tree for quick searching */
  int nVRetTagts;
  RETTAGT_TREE trVRetTagts;
  int nDRetTagts;
  RETTAGT_TREE trDRetTagts;

  int nThisNexts;
  ADDR_CHAIN *liThisNexts;

  /**All derived classes of this class.
   * Because a class may have many derived classes, so for fast searching
   * we use a tree instead of a list to store them. One edges is to itself.
   */
  int nDervClasses;
  CHGEDGE_TREE trDervClasses;

  /**A list of all its ancestors
   * Itself is also in the list */
  int nAncestors;
  ADDR_CHAIN *liAncestors;

  /* Used for chaining CH analysis results */
  CHGNODE *chain;

  /* Random hash parameters. */
  HASH_PARAM params[];

  void init()
  {
    trVRetInsns = RB_INITIALIZER(&trVRetInsns);
    trDRetInsns = RB_INITIALIZER(&trDRetInsns);
    trVRetTagts = RB_INITIALIZER(&trVRetTagts);
    trDRetTagts = RB_INITIALIZER(&trDRetTagts);
    trDervClasses = RB_INITIALIZER(&trDervClasses);
  }
};

struct CHGNODE_ENTRY {
  RB_ENTRY(CHGNODE_ENTRY) entry;
  CHGNODE n;

  static int compare(const CHGNODE_ENTRY *ae, const CHGNODE_ENTRY *be)
  {
    const CHGNODE &a = ae->n;
    const CHGNODE &b = be->n;
    if (a.nClassID == b.nClassID)
      return 0;
    else
      return (a.nClassID < b.nClassID) ? -1 : 1;
  }
};
RB_HEAD(CHGNODE_TREE, CHGNODE_ENTRY);

/****************************************************************************/
/* VLOOM TABLE                                                              */
/****************************************************************************/
/*
 * The table is the main VLOOM state.  It is implemented using a RB-tree.
 * Note: we do not use std::map etc. to avoid introducing dependencies.
 */
struct ElfSymb;
struct ElfRela;
struct DERV_INFO;
struct EnvRuntime;
class MemMgr;
class CHGVisitor;
class BloomFilterMgr;

struct VLOOM_SYMBOL;
class VLOOM_CHA {
  // RB_GENERATE(RETTAGT_TREE, RETTAGT_ENTRY, entry, RETTAGT_ENTRY::compare);
  RB_GENERATE(RETTAGT_TREE, RETTAGT_ENTRY, entry, RETTAGT_ENTRY::compare);
  RB_GENERATE(RETINSN_TREE, RETINSN_ENTRY, entry, RETINSN_ENTRY::compare);
  RB_GENERATE(CHGEDGE_TREE, CHGEDGE_ENTRY, entry, CHGEDGE_ENTRY::compare);
  RB_GENERATE(CHGNODE_TREE, CHGNODE_ENTRY, entry, CHGNODE_ENTRY::compare);

private:
/* class hierachy graph */
/* The instance of graph */
#define CHGNODE_TREE_RB_MIN(table) CHGNODE_TREE_RB_MINMAX(table, -1)
  CHGNODE_TREE mVloomCHG;

  size_t mTotalVPTRs;    // the total number of vptrs stored in this graph
  size_t mTotalRetTagts; // the total number of return-targets stored in this graph

public:
  /* Get an exisiting CHGNode or create a new one */
  CHGNODE *getORaddCHGNode(size_t hash_id);
  void delCHGNode(size_t hash_id);
  int getCHGNodeNum(void);

public:
  struct CHAConfig {
    uint tVCFITestMode;       // Mode affect stroing information
    uint nHashNum;            // Total number of hash functions
    const char *pszFFIdvFile; // white list files
    const char *pszRTenvFile;
    const char *pszExtraFile;

    std::vector<char *> vecRTEnv; // White list from libc.so
    /* map hash(base_class, derv_class) into ulong */
    std::map<size_t, DERV_INFO *> mapFFIdv; // white list for foreign languages
    std::map<size_t, DERV_INFO *> mapExtra; // Extra white list
  };

private:
  CHAConfig mConf;
  MemMgr *mMM;

  CHGNODE *mAnalyzedNodes; // A chain of nodes that have just been updated

public:
  VLOOM_CHA(EnvRuntime *env);
  ~VLOOM_CHA();

  /* Prepare to start a pass of CHA */
  bool initCHAPass(void);
  void finiCHAPass(void);

  /* returns a chain of updated CHGNODEs */
  CHGNODE *getUpdatedCHGNodes(void);

  /* analysis class hierachy & parse vcall-sites */
  bool doAnalyze(void *map_symbs, void *map_relas);

  /* use a callback function to traversal all CHGraph nodes */
  bool visitCHGNode(CHGVisitor &vtor);
  bool visitCHGTree(CHGVisitor &vtor);
  bool visitCHGDerv(CHGVisitor &vtor, CHGNODE *node);
  size_t countNumTargets(CHGNODE *node);

  // Collect targets in terms of class hierarchy tree
  bool collectCHGNodes(std::set<CHGNODE *> &setAddr);
  bool collectDervClasses(std::set<CHGNODE *> &setAddr, CHGNODE *node);
  bool collectVPTRs(std::set<ulong> &setAddr, CHGNODE *node);
  bool collectVRetTagts(std::set<ulong> &setAddr, CHGNODE *node, RETINSN_INFO *insn);
  bool collectVRetInsns(std::set<RETINSN_INFO *> &setRetInsn, CHGNODE *node);
  bool collectDRetTagts(std::set<ulong> &setAddr, CHGNODE *node, RETINSN_INFO *insn);
  bool collectDRetInsns(std::set<RETINSN_INFO *> &setRetInsn, CHGNODE *node);

private:
  friend BloomFilterMgr;
  void chainUpdatedCHGNode(CHGNODE *n);
  bool _doClassAnalysis(void *map_symbs);
  bool _doClangVtableAnalysis(ElfSymb *sym, const char *symbol);
  bool _doRustVtableAnalysis(ElfSymb *sym, const char *symbol);
  bool _doVptrAnalysis(ElfSymb *sym, const char *symbol);
  bool _doVCallAnalysis(ElfSymb *sym, const char *symbol);
  bool _doVRettagtAnalysis(ElfSymb *sym, const char *symbol);
  bool _doDRettagtAnalysis(ElfSymb *sym, const char *symbol);
  bool _doThisNextAnalysis(ElfSymb *sym, const char *symbol);
  bool _doRettagtAnalysis(ElfSymb *sym, const char *symbol, int type);
  bool _doVRetinsnAnalysis(ElfSymb *sym, const char *symbol);
  bool _doDRetinsnAnalysis(ElfSymb *sym, const char *symbol);
  bool _doRetinsnAnalysis(ElfSymb *sym, const char *symbol, bool bVMethod = true);

  /* Deal with relocation entries in batch mode */
  bool _doVCallAnalysis(void *map_relas);

  /* add vtables */
  VTABLE_INFO *addVtable(CHGNODE *entry, VTABLE_INFO *info);

  /* add new derivation relationship */
  CHGEDGE *addDerivation(DERV_INFO *info);

  // void VLOOM_CHA::vloom_patch_vcalls(FILE_INFO &info);
  VCALL_INFO *addVCallSite(CHGNODE *entry, VCALL_INFO *info);
  RETTAGT_INFO *addRetTagt(CHGNODE *entry, RETTAGT_INFO *info, int type);
  RETINSN_INFO *addRetInsn(CHGNODE *entry, RETINSN_INFO *info, bool bVMethod);

  /* Read in white lists */
  bool _readDervInfo(const char *pszFName, std::map<size_t, DERV_INFO *> &mapInfo);
  bool _readStrings(const char *pszFName, std::vector<char *> &vecStr);
  void readWhiteLists();
};

/* Each CHGNODE is mapped to a certain vtable-name.
 * However, there are some corner cases where one vtable-name is used by
 * multiple VTABLEs. So, there is a vtable list in this data structure.
 */
/* Interface for external code */
const char *GetVloomSymbolKeyName(CHGNODE *entry);
const char *GetVloomSymbolDmgName(CHGNODE *entry);

#define KEYNAME(entry) GetVloomSymbolKeyName(entry)
#define RAWNAME(entry) GetVloomSymbolRawName(entry)
#define DMGNAME(entry) GetVloomSymbolDmgName(entry)

class CHGVisitor {
public:
  virtual bool visitNode(CHGNODE *node) { return true; }
  virtual bool visitDerv(CHGNODE *from, CHGNODE *to, CHGEDGE *edge) { return true; }
  virtual bool visitTree(CHGNODE *from, CHGNODE *to, CHGEDGE *edge) { return true; }
};

ulong vloom_profiler_whitelist(ulong vcallsite, ulong vptr);

#endif //_VLOOM_CHA_H__