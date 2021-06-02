#include "bloom.h"
#include "cha.h"
#include "config.h"
#include "hash.h"
#include "logging.h"
#include "mm.h"
#include "patch.h"
#include "utils.h"
#include <assert.h>
#include <set>
#include <sys/mman.h>

/****************************************************************************/
/* VLOOM BLOOM TABLE                                                        */
/****************************************************************************/
// #define VLOOM_BLOOM_BASE 0x0000200000000000ull
// #define VLOOM_BLOOM_SIZE 0x0000400000000000ull
// #define VLOOM_BLOOM_MASK (VLOOM_BLOOM_SIZE - 1)

// #define VLOOM_BLOOM32_BASE 0x0000000060000000ull
// #define VLOOM_BLOOM32_SIZE 0x0000000010000000ull
// #define VLOOM_BLOOM32_MASK (VLOOM_BLOOM32_SIZE - 1)

/****************************************************************************/
/* BloomFilter                                                              */
/****************************************************************************/
/**
 * @brief Construct a new Bloom Filter:: Bloom Filter object
 *
 * @param config System-wide configuration
 * @param bf_size Size of the first hash-table
 */
BloomFilter::BloomFilter(EnvRuntime *config, size_t num_entries)
{ /* initialize configuration */
  mMM = (MemMgr *)config->pMemMgr;
  mArrHPs = config->arHPs;
  mHashNum = config->nHashNum;

  mBFEntAlign = config->nHashEntBytes;
  mSatLowerBound = config->nSatLoBound;
  mSatUpperBound = config->nSatHiBound;

  size_t bfsize = num_entries * mSatLowerBound * mBFEntAlign;
  bfsize = (bfsize + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1));
  mHashTables[0].ba = createHashTable(bfsize);
  mHashTables[0].sz = bfsize;
  mHashTables[0].et = bfsize / mBFEntAlign;
  mHashTables[1].ba = NULL; // No a second HashTable
  mCurTbl = &mHashTables[0];

  mRefCnt = 1;
}

BloomFilter::~BloomFilter()
{
  BFHashTable *ht = mHashTables;
  for (int i = 0; i < 2; i++, ht++) {
    if (ht->ba != NULL)
      munmap(ht->ba, ht->sz);
  }
}

/**
 * @brief Create a new hash table at a random address.
 *
 * @param bf_size the size of hash-table, already rounded to page-size
 * @return void*
 */
void *BloomFilter::createHashTable(size_t bf_size)
{
#define FATAL_RESERVE "failed to reserve %Y%zu%D bytes for BLOOM filter: %s"
#define FATAL_ADVISE "failed to advise random access for BLOOM filter: %s"
#define MSG_MMAP "Create a bloom filter beginning at address %p with 0x%x bytes"
#define MAP_FLAG (MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE)

  uint64_t rand64 = mMM->randInt64();
  rand64 = rand64 & 0x7FFFFFFFFFFF; // converted to a valid canonical address
  void *base = (void *)(rand64 & ~(PAGE_SIZE - 1));
  void *ptr = mmap(base, bf_size, PROT_READ | PROT_WRITE, MAP_FLAG, -1, 0);

  if (ptr != base)
    VLOOM_LOG(VLL_TRACE, MSG_MMAP, ptr, bf_size);

  if (madvise(ptr, bf_size, MADV_RANDOM) < 0)
    VLOOM_LOG(VLL_FATAL, FATAL_ADVISE, strerror(errno));

  return ptr;
}

/**
 * @brief if needs, try to expand the size of hash-tables
 *
 * @param new_num_targets
 * @return true
 * @return false
 */
bool BloomFilter::tryExpandSize(size_t new_num_targets)
{
  // number of Bloom-filter entries would put on existing bitmaps
  size_t nBFSize; // bitmap size in bytes
  void *pBlmflt;

  /* stil under the upper bound? */
  if (new_num_targets < mCurTbl->et / mSatUpperBound)
    return true;

  /* creat new hash-table */
  size_t newsize = new_num_targets * mSatLowerBound * mBFEntAlign;
  newsize = (newsize + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1));
  void *newTbl = createHashTable(newsize);

  /* We create a third BFHashTable? */
  if (mHashTables[1].ba != NULL) {
    BFHashTable *ht = &mHashTables[0];
    /* dump the whole things from mHashTables[0] to newTbl */
    memcpy(newTbl, ht->ba, ht->sz);
    memcpy(&mHashTables[0], &mHashTables[1], sizeof(BFHashTable));
  }

  mCurTbl = &mHashTables[1];
  mCurTbl->ba = newTbl;
  mCurTbl->sz = newsize;
  mCurTbl->et = newsize / mBFEntAlign;

  return true;
}

/**
 * @brief Update bloom-filter for a CHGNODE
 *
 * @param cha
 * @param node
 * @param num_targets The number of targets would put into the hash-tables
 * @return true
 * @return false
 */
bool BloomFilter::updateForCHGNode(VLOOM_CHA *cha, CHGNODE *node)
{
  mCHA = cha;
  mCurNode = node;

  // Our LLVM-compiler doesn't generate _VPTR_Dxx_Bxx symbols if node doesn't have VTABLE
  if (node->bVerified) {
    _updateForVcalls();
    _updateForVRetInsns();
  }
  _updateForDRetInsns();
  return true;
}

/**
 * @brief Update the bloom-filter for the virtual-calls issued with this calss as static type;
 *
 * @return true
 * @return false
 */
bool BloomFilter::_updateForVcalls()
{
  /* check status first */
  if (!mCurNode->bNewDervCls || mCurNode->bUpdtBF4Dervs)
    return true;
  else
    mCurNode->bUpdtBF4Dervs = true;

  std::set<ulong> setAddr;
  mCHA->collectVPTRs(setAddr, mCurNode);

  /* Generate bloom filter entries for each vcall-site  */
  for (VCALL_INFO *vci = mCurNode->liVcalls; vci != NULL; vci = vci->next) {
    HASH_PARAM *params = vci->params;
    for (auto B = setAddr.begin(), E = setAddr.end(); B != E; B++) {
      void *vptr = (void *)*B;
      VLOOM_LOG(VLL_TRACE, "VCall %s@%p has a target %p", DMGNAME(mCurNode), vci->addr, vptr);
      _updateEntry(params, vptr);
    }
  }

  return true;
}

/**
 * @brief Update the bloom-filter for RET instructions in the methods;
 *
 * @return true
 * @return false
 */
bool BloomFilter::_updateForDRetInsns()
{
  /* check status first */
  if (!mCurNode->bNewDRetTagt || mCurNode->bUpdtBF4DTagts)
    return true;
  else
    mCurNode->bUpdtBF4DTagts = true;

  std::set<RETINSN_INFO *> setInsns;
  std::set<ulong> setAddr;
  /* Return instructions of non-virtual functions */

  mCHA->collectDRetInsns(setInsns, mCurNode);
  for (auto B = setInsns.begin(), E = setInsns.end(); B != E; B++) {
    // Even ri may have more than one instruction, but they share the same BF.
    // Check codepather for consistency
    RETINSN_INFO *ri = *B;

    setAddr.clear();
    mCHA->collectDRetTagts(setAddr, mCurNode, ri);

    HASH_PARAM *params = ri->params;
    for (auto B = setAddr.begin(), E = setAddr.end(); B != E; B++) {
      void *vptr = (void *)*B;
      /* Log with the address of 1st instruction */
      VLOOM_LOG(VLL_TRACE, "DRet %G%s%D@%Y%p%D has a target %p", DMGNAME(mCurNode), ri->chain->addr, vptr);
      _updateEntry(params, vptr);
    }
  }
  return true;
}

bool BloomFilter::_updateForVRetInsns()
{
  /* check status first */
  if (mCurNode->bUpdtBF4VTagts)
    return true;
  else
    mCurNode->bUpdtBF4VTagts = true;

  std::set<RETINSN_INFO *> setInsns;
  std::set<ulong> setAddr;
  /* Return instructions of non-virtual functions */
  setInsns.clear();
  mCHA->collectVRetInsns(setInsns, mCurNode);

  for (auto B = setInsns.begin(), E = setInsns.end(); B != E; B++) {
    // Even ri may have more than one instruction, but they share the same BF.
    // Check codepather for consistency
    RETINSN_INFO *ri = *B;

    setAddr.clear();
    mCHA->collectVRetTagts(setAddr, mCurNode, ri);

    HASH_PARAM *params = ri->params;
    for (auto B = setAddr.begin(), E = setAddr.end(); B != E; B++) {
      void *vptr = (void *)*B;
      /* Log with the address of 1st instruction */
      VLOOM_LOG(VLL_TRACE, "VRet %G%s%D@%Y%p%D has a target %p", DMGNAME(mCurNode), ri->chain->addr, vptr);
      _updateEntry(params, vptr);
    }
  }
  return true;
}

/**
 * @brief Update a bloom-filter entry for the target address VPTR
 *
 * @param params randomized parameters
 * @param vptr target address
 * @return true
 * @return false
 */
bool BloomFilter::_updateEntry(HASH_PARAM *params, void *vptr)
{
#define MSG_BFENT "add BLOOM filter entry %Y%p%D (%Y%p+%u*0x%.8x%D) for %G%s%D with address %p"
  for (uint k = 0; k < mHashNum; k++) {
    /* Calculate the hash-slot in Bloom-filter */
    uint8_t *pBFBaseAddr = (uint8_t *)mCurTbl->ba;
    uint32_t hval = mArrHPs[k]->fHash(vptr, pBFBaseAddr, params[k].n64, params[k].n32);
    hval = hval % mCurTbl->et; // round to bitmap size

    void *ptr = NULL;
    if (mBFEntAlign == 1) {
      uint8_t *addr = (uint8_t *)mCurTbl->ba + hval * mBFEntAlign;
      *addr = *addr + 1;
      ptr = addr;
    }
    else if (mBFEntAlign == 2) {
      uint16_t *addr = (uint16_t *)((uint8_t *)mCurTbl->ba + hval * mBFEntAlign);
      *addr = *addr + 1;
      ptr = addr;
    }
    else if (mBFEntAlign == 4) {
      uint32_t *addr = (uint32_t *)((uint8_t *)mCurTbl->ba + hval * mBFEntAlign);
      *addr = *addr + 1;
      ptr = addr;
    }
    else
      _UNREACHABLE;

    VLOOM_LOG(VLL_TRACE, MSG_BFENT, ptr, mCurTbl->ba, mBFEntAlign, hval, DMGNAME(mCurNode), vptr);
  }
  return true;
}

/* Set protection permissions on bloom filter */
void BloomFilter::setBFProtected()
{
#define MSG_FAIL_PROTECT "failed to set page permissions for BLOOM filter: %s"
#ifdef XOM_SUPPORT
  // All unused pages are PROT_NONE
  if (mprotect(mCurTbl->ba, mCurTbl->sz, PROT_NONE) < 0)
    VLOOM_LOG(VLL_FATAL, MSG_FAIL_PROTECT, "%s", strerror(errno));
#else
  // All used pages are PROT_READ
  if (mprotect(mCurTbl->ba, mCurTbl->sz, PROT_READ) < 0)
    VLOOM_LOG(VLL_FATAL, MSG_FAIL_PROTECT, strerror(errno));
#endif
}

/* Set protection permissions on bloom filter */
void BloomFilter::setBFUnprotected()
{
#define MSG_FAIL_UNPROTECT "failed to set page permissions for BLOOM filter: %s"
  if (mprotect(mCurTbl->ba, mCurTbl->sz, PROT_READ | PROT_WRITE) < 0)
    VLOOM_LOG(VLL_FATAL, MSG_FAIL_UNPROTECT, strerror(errno));
}

/****************************************************************************/
/* BloomFilterMgr                                                           */
/****************************************************************************/
/**
 * @env: input configuration data
 * @conf: keep parsing result
 */
BloomFilterMgr::BloomFilterMgr(EnvRuntime *conf)
{
  assert(conf != NULL);
  mConf = conf;

  /* VLOOM's private memory management system */
  mMM = (MemMgr *)conf->pMemMgr;
}

BloomFilterMgr::~BloomFilterMgr() {}

/**
 * @paConf: input
 * @bfConf: output
 */
void BloomFilterMgr::FixEnvRuntime(EnvRuntime *rt)
{
  EnvConfig *conf = rt->pEnvConf;
  if (conf == NULL)
    return;

  rt->bBlmFPCentric = conf->bBlmFPCentric;
  rt->nHashTblBytes = conf->nHashTableBits;
  rt->nHashTblBytes = (1 << conf->nHashTableBits);
  rt->nHashEntBytes = conf->nHashEntBytes;

  /* Update configuration */
  if (rt->nHashEntBytes > 2)
    rt->nHashEntBytes = 4;
  else if (rt->nHashEntBytes > 1)
    rt->nHashEntBytes = 2;
  else
    rt->nHashEntBytes = 1;
}

BloomFilterMgr *BloomFilterMgr::GetBFMgr(EnvRuntime *rt)
{
  if (rt->bBlmFPCentric)
    return new BFMgrCentric(rt);
  else
    return new BFMgrSeperate(rt);
}

bool BloomFilterMgr::updateBloomFilters(VLOOM_CHA *cha)
{
  std::set<CHGNODE *> setNodes;
  if (!cha->collectCHGNodes(setNodes))
    return false;

  bool res = _updateBloomFilters(cha, setNodes);
  setNodes.clear();
  return res;
}

bool BloomFilterMgr::updateBloomFilters(VLOOM_CHA *cha, CHGNODE *chain)
{
  std::set<CHGNODE *> setNodes;
  for (CHGNODE *node = chain; node != NULL; node = node->chain) {
    if (node->bNewVRetTagt) {                  // collect all its derived classes
      cha->collectDervClasses(setNodes, node); // itself is also a derived class
    }
    else if (node->bNewDervCls || node->bNewDRetTagt) {
      setNodes.insert(node);
    }
  }

  bool res = _updateBloomFilters(cha, setNodes);

  /* On behalf of VLOOM_CHA, it depends on the chain to reset status of CHGNodes */
  for (auto B = setNodes.begin(), E = setNodes.end(); B != E; B++)
    cha->chainUpdatedCHGNode(*B);

  setNodes.clear();
  return res;
}

void BloomFilterMgr::releaseBloomFilter(CHGNODE *node)
{
  BloomFilter *bf = (BloomFilter *)node->pBloomFilter;
  bf->mRefCnt--;
  if (bf->mRefCnt == 0)
    delete bf;
}

/****************************BFMgrCentric*************************************/

BFMgrCentric::BFMgrCentric(EnvRuntime *rt) : BloomFilterMgr(rt)
{
  /* The memory size of BLOOM FILTER */
  if (mConf->nHashTblBytes < 4 * PAGE_SIZE)
    VLOOM_LOG(VLL_WARN, "Bloom-filter size is %ldB, but should be >0x1000", mConf->nHashTblBytes);

  size_t nTotalTargets = mConf->nHashTblBytes / mConf->nHashEntBytes / mConf->nSatLoBound;
  mBlmflt = new BloomFilter(rt, nTotalTargets);
}

BFMgrCentric::~BFMgrCentric() { delete mBlmflt; }

bool BFMgrCentric::_updateBloomFilters(VLOOM_CHA *cha, std::set<CHGNODE *> &setNodes)
{
  size_t nTotalTargets = 0;
  for (auto B = setNodes.begin(), E = setNodes.end(); B != E; B++) {
    CHGNODE *node = *B;
    nTotalTargets += cha->countNumTargets(node);
    BloomFilter *pBlmflt = (BloomFilter *)node->pBloomFilter;
    if (pBlmflt == NULL)
      node->pBloomFilter = mBlmflt; // Codepatcher needs to this data pointer
  }

  // notify the BloomFilter to expand its size */
  mBlmflt->tryExpandSize(nTotalTargets);

  mBlmflt->setBFUnprotected();
  for (auto B = setNodes.begin(), E = setNodes.end(); B != E; B++)
    mBlmflt->updateForCHGNode(mCHA, *B);
  mBlmflt->setBFUnprotected();

  return true;
}

/****************************BFMgrSeperate*************************************/

bool BFMgrSeperate::_updateBloomFilters(VLOOM_CHA *cha, std::set<CHGNODE *> &setNodes)
{
  size_t nTotalTargets = 0;
  for (auto B = setNodes.begin(), E = setNodes.end(); B != E; B++) {
    CHGNODE *node = *B;
    BloomFilter *pBlmflt = (BloomFilter *)node->pBloomFilter;
    size_t nTargets = cha->countNumTargets(node);
    if (pBlmflt == NULL)
      node->pBloomFilter = pBlmflt = new BloomFilter(mConf, nTargets);
    else
      pBlmflt->tryExpandSize(nTargets);

    pBlmflt->setBFUnprotected();
    pBlmflt->updateForCHGNode(mCHA, node);
    pBlmflt->setBFUnprotected();
  }
  return true;
}