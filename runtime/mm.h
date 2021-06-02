#ifndef _VLOOM_MM_H__
#define _VLOOM_MM_H__

#include "utils.h"
#include <stdint.h>

/****************************************************************************/
/* VLOOM MALLOC                                                             */
/****************************************************************************/
class MemMgr {
private:
  struct MMChunk {
    uint8_t *pBaseAddr; // Base addres of this chunk;
    size_t nTotalSize;  // Size of this chunk;
    size_t nUsed;       // Size of used bytes;
    size_t nLeft;       // Size of unused bytes;
    size_t nNextOft;    // Next offset to  be allocated;

    uint8_t *pRandSeed;
    size_t nRandSeedNext;
  } mMMChunk;

  static MemMgr *mSingleton; // Singleton mode
  int mRefCounter;           // reference counter to mSingleton object

  static const char *mRandFile; // ranmdomized data soruce

  MemMgr(void);
  ~MemMgr(void);

public:
  static MemMgr *PickInstance();
  static void DropInstance();

  /* set mprotect flags to memory chunk */
  void mprotect(int prot);

  /* Query chunk status */
  size_t getUsedSize(void);
  size_t getLeftSize(void);

  /* memory allocation and doFree */
  void *doMalloc(size_t size);
  void doFree(void *ptr);

  /* duplicate a string in chunk */
  char *doStrdup(const char *str);

  static void SetRandFile(const char *file_path);
  void randBuffer(void *buf_0, size_t len);
  uint64_t randInt64(void);
  uint32_t randInt32(void);

private:
  void randPagesize(void *buf);
};

#endif // define _VLOOM_MM_H__