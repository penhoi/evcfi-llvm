#include "mm.h"
#include "config.h"
#include "logging.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

/****************************************************************************/
/* VLOOM MALLOC                                                             */
/****************************************************************************/
MemMgr *MemMgr::mSingleton = NULL;

/* memory management system */
MemMgr *MemMgr::PickInstance(void)
{
  if (mSingleton == NULL)
    mSingleton = new MemMgr();

  mSingleton->mRefCounter++;
  return mSingleton;
}

void MemMgr::DropInstance(void)
{
  mSingleton->mRefCounter--;
  if (mSingleton->mRefCounter > 0)
    return;

  if (mSingleton != NULL)
    delete mSingleton;

  mSingleton = NULL;
}

/*
 * Initialize VLOOM doMalloc.
 */
MemMgr::MemMgr(void)
{
  VLOOM_LOG(VLL_TRACE, "Initialize VLOOM's private memory management system");

#define VLOOM_MALLOC_SIZE (1024 * 1024 * 1024) // 1GB
  size_t size = VLOOM_MALLOC_SIZE;
  int prots = PROT_READ | PROT_WRITE;
  int flags = MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS;
  void *addr = mmap(NULL, size, prots, flags, -1, 0);

#define ERR_MMAP_FAIL "failed to reserve %zu bytes for VLOOM memory: %s"
  if (addr == MAP_FAILED)
    VLOOM_LOG(VLL_FATAL, ERR_MMAP_FAIL, size, strerror(errno));

#define ERR_MADV_FAIL "failed to exclude memory from core dumps: %s"
  if (madvise(addr, size, MADV_DONTDUMP) < 0)
    VLOOM_LOG(VLL_FATAL, ERR_MADV_FAIL, strerror(errno));

  mMMChunk.pBaseAddr = (uint8_t *)addr;
  mMMChunk.nTotalSize = size;
  mMMChunk.nLeft = mMMChunk.nTotalSize;
  mMMChunk.nUsed = 0;
  mMMChunk.nNextOft = 0;

  mMMChunk.pRandSeed = NULL;
  mMMChunk.nRandSeedNext = 0;

  mRefCounter = 0;
}

MemMgr::~MemMgr(void)
{
  if (mMMChunk.pBaseAddr != NULL)
    munmap(mMMChunk.pBaseAddr, mMMChunk.nTotalSize);

  mMMChunk.pBaseAddr = NULL;
  assert(mRefCounter == 0);

  VLOOM_LOG(VLL_TRACE, "Finalize VLOOM's private memory management system");
}

/*
 * VLOOM protect memory.
 */
void MemMgr::mprotect(int prot)
{
#define ERR_MPROTECT "failed to protect VLOOM memory: %s"
  if (::mprotect(mMMChunk.pBaseAddr, mMMChunk.nTotalSize, prot) < 0) {
    VLOOM_LOG(VLL_FATAL, ERR_MPROTECT, strerror(errno));
  }
}

/*
 * VLOOM doMalloc.
 */
void *MemMgr::doMalloc(size_t size)
{
  assert(mMMChunk.pBaseAddr != NULL);
  /* alignment */
  size_t allocSZ = size + size % sizeof(void *);

  if (allocSZ > mMMChunk.nLeft)
    VLOOM_LOG(VLL_FATAL, "failed to allocate %zu bytes: %s", strerror(ENOMEM));

  void *ptr = mMMChunk.pBaseAddr + mMMChunk.nNextOft;
  mMMChunk.nUsed += allocSZ;
  mMMChunk.nNextOft += allocSZ;
  mMMChunk.nLeft -= allocSZ;

  /* zero-ed to avoid info leaking */
  memset(ptr, 0, size);
  return ptr;
}

void MemMgr::doFree(void *ptr)
{ /* not implemented */
}

/*
 * VLOOM strdup
 */
char *MemMgr::doStrdup(const char *str)
{
  size_t len = strlen(str);
  char *str2 = (char *)doMalloc(len + 1);
  memcpy(str2, str, len);
  str2[len] = 0;

  return str2;
}

/*
 * VLOOM memory usage.
 */
size_t MemMgr::getUsedSize(void) { return mMMChunk.nUsed; }

size_t MemMgr::getLeftSize(void) { return mMMChunk.nLeft; }

/****************************************************************************/
/* VLOOM RANDOM                                                             */
/****************************************************************************/
const char *MemMgr::mRandFile = "/dev/urandom";

void MemMgr::SetRandFile(const char *file_path) { mRandFile = file_path; }

/*
 * Get a page of randomized bytes.
 */
void MemMgr::randPagesize(void *buf)
{
  const char *path = mRandFile;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    VLOOM_LOG(VLL_FATAL, "failed to open \"%s\": %s", path, strerror(errno));

  size_t size = VLOOM_PAGE_SIZE;
  ssize_t r = read(fd, buf, size);
  if (r < 0)
    VLOOM_LOG(VLL_FATAL, "failed to read \"%s\": %s", path, strerror(errno));
  if (r != size)
    VLOOM_LOG(VLL_FATAL, "failed to read %zu bytes from \"%s\"", size, path);
  if (close(fd) < 0)
    VLOOM_LOG(VLL_FATAL, "failed to close \"%s\": %s", path, strerror(errno));
}

/*
 * VLOOM CSRNG
 */
void MemMgr::randBuffer(void *buf_0, size_t len)
{
  uint8_t *&vloom_seed = mMMChunk.pRandSeed;
  size_t &vloom_seed_next = mMMChunk.nRandSeedNext;

  uint8_t *buf = (uint8_t *)buf_0;
  uint8_t *end = buf + len;

  if (vloom_seed == NULL) {
    vloom_seed = (uint8_t *)doMalloc(VLOOM_PAGE_SIZE);
    vloom_seed_next = SIZE_MAX;
  }
  while (buf < end) {
    if (vloom_seed_next >= VLOOM_PAGE_SIZE) {
      randPagesize(vloom_seed);
      vloom_seed_next = 0;
    }
    *buf++ = vloom_seed[vloom_seed_next++];
  }
}

uint64_t MemMgr::randInt64(void)
{
  uint64_t r = 0;

  randBuffer(&r, sizeof(r));
  return r;
}

uint32_t MemMgr::randInt32(void)
{
  uint32_t r = 0;

  randBuffer(&r, sizeof(r));
  return r;
}