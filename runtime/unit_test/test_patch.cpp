#define private public

#include "../hash.h"
#include "../patch.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <sys/mman.h>

#define PAGE_SIZE 0x1000
typedef unsigned char BYTE;

TEST_GROUP(test_vloompatch){};

TEST(test_vloompatch, vcfichecker)
{
  BYTE *szCodeBuf = (BYTE *)mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  /* set PatchingConfig */
  EnvConfig *conf = new EnvConfig();
  conf->nHashNum = 1;
  conf->arFuncName[0] = utils_strdup("add32");
  conf->tRuntimeMode = VM_ENFORCE_VCFI;

  EnvRuntime *rt = new EnvRuntime(conf);
  VLOOM_CSPatcher::FixEnvRuntime(rt);
  VLOOM_CSPatcher *patcher = new VLOOM_CSPatcher(rt);

  long addr = (long)szCodeBuf;
  addr = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1) + 0x100;

  VCALL_INFO pe1 = {
      65, 4,                 // size = 64; regs = 4;
      (uint8_t *)addr, NULL, //  addr = szCodeBuf; next = NULL
  };

  VCALL_INFO pe2 = {
      65, 4,                         // size = 64; regs = 4;
      (uint8_t *)(addr + 256), &pe1, // addr = szCodeBuf; next = NULL
  };
  HASH_PARAM params{0, 0};
  uint8_t *base = NULL;

  patcher->mBloomAddr = base;
  patcher->patchVCFIChecker(&pe1, &params);
  patcher->patchVCFIChecker(&pe2, &params);

  size_t nSize = sizeof(CHGNODE) + sizeof(HASH_PARAM) * 2;
  CHGNODE *node = (CHGNODE *)malloc(nSize);
  memset(node, 0, nSize);
  node->liVcalls = &pe2;

  patcher->patchNewCS(node, base);

  free(node);
  delete patcher;
  delete rt;
  delete conf;

  munmap(szCodeBuf, PAGE_SIZE * 2);
}

TEST(test_vloompatch, vcallcounter)
{
  BYTE *szCodeBuf =
      (BYTE *)mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);

  /* set PatchingConfig */
  EnvRuntime *conf = new EnvRuntime(NULL);
  conf->tRuntimeMode = VM_ENFORCE_VCFI;
  conf->pCounterAddr = (ulong *)szCodeBuf;

  VLOOM_CSPatcher *patcher = new VLOOM_CSPatcher(conf);

  long addr = (long)szCodeBuf;
  addr = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1) + 0x100;

  VCALL_INFO pe1 = {
      64, 4,                 // size = 64; regs = 4;
      (uint8_t *)addr, NULL, //  addr = szCodeBuf; next = NULL
  };
  patcher->patchVCallCounter(&pe1, NULL);

  static const uint8_t szLockinc[] = {0xF0, 0x48, 0xFF, 0x04, 0x25, 0x00, 0x00, 0x01, 0x00};
  static const uint nLockinc = sizeof(szLockinc);
  static const uint nConstOft = 5;

  char *pStart = (char *)(addr - nLockinc);
  CHECK_TRUE(memcmp(pStart, szLockinc, nConstOft) == 0);

  uint32_t *pConst = (uint32_t *)(pStart + nConstOft);
  CHECK_EQUAL(*(uint32_t *)&szCodeBuf, *(uint32_t *)pConst);

  delete patcher;
  delete conf;

  munmap(szCodeBuf, PAGE_SIZE * 2);
}

int main(int ac, char **av) { return CommandLineTestRunner::RunAllTests(ac, av); }