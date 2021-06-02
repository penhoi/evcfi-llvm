/**
 * Test the memory management system of VLOOM
 */
#define private public

#include "../mm.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(test_vloommm){};

TEST(test_vloommm, mallocfree)
{
  MemMgr *mm = MemMgr::PickInstance();
  size_t totalSize = mm->getLeftSize();

  void *pBuf1 = NULL;
  void *pBuf2 = NULL;

  pBuf1 = mm->doMalloc(64);
  pBuf2 = mm->doMalloc(64);
  CHECK_EQUAL(0, (long)pBuf1 % 4);
  CHECK_EQUAL(0, (long)pBuf2 % 4);

  CHECK(pBuf1 != NULL);
  CHECK(pBuf2 != NULL);
  CHECK(pBuf1 != pBuf2);

  /* strdup */
  const char *str = "mmstrdup";
  char *clone = mm->doStrdup(str);
  STRCMP_EQUAL(str, clone);
  CHECK_EQUAL(0, clone[strlen(clone)]);

  /* status */
  size_t used = mm->getUsedSize();
  size_t left = mm->getLeftSize();

  CHECK_EQUAL(totalSize, used + left);

  MemMgr::DropInstance();
}

TEST(test_vloommm, randint)
{
  MemMgr *mm = MemMgr::PickInstance();
  uint64_t d64 = mm->randInt64();
  uint32_t d32 = mm->randInt32();

  CHECK(d64 != 0);
  CHECK(d32 != 0);

  CHECK((uint32_t)d64 != d32);
  MemMgr::DropInstance();
}

TEST(test_vloommm, randbuf)
{
  MemMgr *mm = MemMgr::PickInstance();
  char szBuf64[64 + 8] = {0};
  char szBuf32[32 + 8] = {0};

  CHECK(szBuf64[0] == 0);
  CHECK(szBuf32[0] == 0);

  mm->randBuffer(szBuf64, 64);
  mm->randBuffer(szBuf32, 32);

  CHECK(szBuf64[0] != 0);
  CHECK(szBuf32[0] != 0);

  CHECK(strncmp(szBuf64, szBuf32, 32) != 0);
  MemMgr::DropInstance();
}

TEST(test_vloommm, disableRandomize)
{
  /* Randomize is enabled by default */
  char szBuf1[64 + 8], szBuf2[64 + 8];
  MemMgr *mm = NULL;

  mm = MemMgr::PickInstance();
  mm->randBuffer(szBuf1, 64);
  MemMgr::DropInstance();

  mm = MemMgr::PickInstance();
  mm->randBuffer(szBuf2, 64);
  MemMgr::DropInstance();

  CHECK(strncmp(szBuf1, szBuf2, 64) != 0);

  /* Disable randomize */
  const char *szCmd = "head -c 8092 /dev/urandom > del.rnd";
  const char *pszFile = "del.rnd";
  system(szCmd);
  MemMgr::SetRandFile(pszFile);

  mm = MemMgr::PickInstance();
  mm->randBuffer(szBuf1, 64);
  MemMgr::DropInstance();

  mm = MemMgr::PickInstance();
  mm->randBuffer(szBuf2, 64);
  MemMgr::DropInstance();

  CHECK(strncmp(szBuf1, szBuf2, 64) == 0);
}

int main(int ac, char **av) { return CommandLineTestRunner::RunAllTests(ac, av); }