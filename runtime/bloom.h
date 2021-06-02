/**
 * @file bloom.h
 * @author Pinghai (pinghaiyuan@gmail.com)
 * @brief CHGNode, BloomFilterMgr and BloomFilter, organized in patient-hospital-doctor modle.
 * CHGNode ask BloomFilterMgr to create a BloomFilter;
 * CHGNode is not allowed to directly send message to BloomFilter;
 * BloomFilter would create/update the bloom-filter in terms of the targets referred by a CHGNode.
 * @version 0.1
 * @date 2021-01-27
 *
 * @copyright Copyright (c) 2021
 *
 */

#ifndef _BLOOM_H__
#define _BLOOM_H__

#include "tree.h"
#include <libelf.h>
#include <map>
#include <set>
#include <string.h>

struct EnvConfig;
struct EnvRuntime;
struct CHGNODE;
class MemMgr;
class VLOOM_CHA;
class CHGVisitor;
struct EnvRuntime;
class BloomFilterMgr;
class VLOOM_CHA;
struct CHGNODE;
struct HASH_PARAM;
struct HPFUNCPAIR;

/**
 * @brief Encapsulate all activies about maitaining a bloomfilter
 * For performance, each instance contains one or two hash-tables.
 * When the saturation reaches the upper bound, a new hash-table is created,
 * After that, all updates would carry on the new table.
 */
class BloomFilter {
  friend BloomFilterMgr;

  struct BFHashTable {
    void *ba;  // base address
    size_t sz; // total size in bytes
    size_t et; // The maximum #entries;
  };

  uint mRefCnt; // reference counter;

  /* configurations */
  MemMgr *mMM;
  HPFUNCPAIR **mArrHPs; // Designate to use a certain  hash functions
  uint mHashNum;        // Total number of hash functions
  uint mBloomFTy;

  /* hash table information */
  BFHashTable mHashTables[2];

  /* the Saturation bound of BFHashTable */
  uint mSatLowerBound;
  uint mSatUpperBound;
  uint mBFEntAlign; // entry alignment boundary

  /* one-pass arguments */
  VLOOM_CHA *mCHA;
  CHGNODE *mCurNode; // current CHGNODE in processing

public:
  BFHashTable *mCurTbl;

public:
  BloomFilter(EnvRuntime *config, size_t bf_size);
  ~BloomFilter();

  void *createHashTable(size_t bf_size);

  /* try to expand the hash-table size */
  bool tryExpandSize(size_t new_num_targets);
  /* dump the content to anther bigger hash-table */
  bool _dumpContent(void *from, void *to);

  /* update entries this bloom filter */
  bool updateForCHGNode(VLOOM_CHA *cha, CHGNODE *node);
  bool _updateForVcalls();
  bool _updateForVRetInsns();
  bool _updateForDRetInsns();
  bool _updateEntry(HASH_PARAM *params, void *vptr);

  /* set permissions on hash-tables */
  void setBFProtected();
  void setBFUnprotected();
};

enum BlmfltPolicy {
  BFP_CENTRIC, // use centric bitmaps, only one or two bitmaps shared by all CHGNODEs
  BFP_SEPERAT, // use seperate bitmaps, each CHGNODE has one or two bitmaps
};

class BloomFilterMgr {
protected:
  EnvRuntime *mConf;
  MemMgr *mMM;
  VLOOM_CHA *mCHA;

  /* the Saturation bound of BloomFilter */
  // uint mSatLowerBound;
  // uint mSatUpperBound;

  // uint mHashNum;        // Total number of hash functions
  // HPFUNCPAIR **mArrHPs; // Designate to use a certain  hash functions
  // uint8_t *mBFBaseAddr;
  // uint mBFHVecBits;
  // uint mBloomFTy;
  // uint mBFAlign;

public:
  BloomFilterMgr(EnvRuntime *conf);
  virtual ~BloomFilterMgr();

  /* EnvRuntime should be fixed according to BF domain knowledge */
  static void FixEnvRuntime(EnvRuntime *rt);
  static BloomFilterMgr *GetBFMgr(EnvRuntime *rt);

  bool updateBloomFilters(VLOOM_CHA *cha);
  bool updateBloomFilters(VLOOM_CHA *cha, CHGNODE *chain);
  virtual bool _updateBloomFilters(VLOOM_CHA *cha, std::set<CHGNODE *> &setNodes) = 0;

  /* A CHGNODE must release its bloomfilter when it is being destroied */
  void releaseBloomFilter(CHGNODE *node);
};

class BFMgrCentric : public BloomFilterMgr {
public:
  BloomFilter *mBlmflt;

  BFMgrCentric(EnvRuntime *rt);
  ~BFMgrCentric();
  virtual bool _updateBloomFilters(VLOOM_CHA *cha, std::set<CHGNODE *> &setNodes);
};

class BFMgrSeperate : public BloomFilterMgr {
public:
  BFMgrSeperate(EnvRuntime *rt) : BloomFilterMgr(rt) {}
  virtual bool _updateBloomFilters(VLOOM_CHA *cha, std::set<CHGNODE *> &setNodes);
};

#endif // _BLOOM_H__
