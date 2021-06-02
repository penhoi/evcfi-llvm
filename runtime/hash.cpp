/**
 * This file defines all available hash funcitons,
 * and their corresponding patching functions.
 */
#include "hash.h"
#include "logging.h"
#include "patch.h"
#include "utils.h"

// Regsiters used in the patch
enum Register_Set {
  RDXRDIRSI,
  R11R10R9,
};
uint gnRegisterSet = RDXRDIRSI;
/*
 * hash = ptr + addend
 */
static uint32_t vloom_hash_add32(const void *ptr, const uint8_t *bloom, uint64_t __unused, uint32_t addend)
{
  // VLOOM_LOG(VLL_WARN, "%p + 0x%.8X = 0x%.8X", ptr, addend, (uint32_t)(uintptr_t)ptr + (uint32_t)addend);
  return (uint32_t)(uintptr_t)ptr + (uint32_t)addend;
}

/*
 * hash = xor(ptr, addend)
 */
static uint32_t vloom_hash_xor32(const void *ptr, const uint8_t *bloom, uint64_t __unused, uint32_t addend)
{
  // VLOOM_LOG(VLL_WARN, "%p + 0x%.8X = 0x%.8X", ptr, addend, (uint32_t)(uintptr_t)ptr + (uint32_t)addend);
  return (uint32_t)(uintptr_t)ptr ^ (uint32_t)addend;
}

/*
 * hash = crc32(accumulator, ptr)
 */
static uint32_t vloom_hash_crc32(const void *ptr, const uint8_t *bloom, uint64_t __unused, uint32_t accumulator)
{
  // VLOOM_LOG(VLL_WARN, "crc32(%p, 0x%.8X) = 0x%.8X (or 0x%.8lX)", ptr, accumulator,
  //           (uint32_t)__builtin_ia32_crc32di((uint64_t)(uintptr_t)ptr, (uint64_t)accumulator),
  //           (uint32_t)__builtin_ia32_crc32di((uint64_t)accumulator, (uint64_t)(uintptr_t)ptr));
  return (uint32_t)__builtin_ia32_crc32di((uint64_t)accumulator, (uint64_t)(uintptr_t)ptr);
}

/*
 * hash = ptr * multiplicand + addend
 */
static uint32_t vloom_hash_mul32(const void *ptr, const uint8_t *bloom, uint64_t multiplicand, uint32_t addend)
{
  // VLOOM_LOG(VLL_WARN, "0x%.8X * %p + 0x%.8X = 0x%.8X", (uint32_t)multiplicand, ptr, addend,
  //           (uint32_t)multiplicand * (uint32_t)(uintptr_t)ptr + addend);
  return (uint32_t)multiplicand * (uint32_t)(uintptr_t)ptr + addend;
}

/*
 * hash = crc32(bloom, ptr * multiplicand)
 */
static uint32_t vloom_hash_mul64crc32(const void *ptr, const uint8_t *bloom, uint64_t multiplicand, uint32_t __unused)
{
  // VLOOM_LOG(VLL_WARN, "tmp = %p*0x%.16lX=0x%.16lX, hash=0x%.8X", ptr, multiplicand, (uint64_t)ptr * multiplicand,
  //           (uint32_t)__builtin_ia32_crc32di((uint64_t)ptr * multiplicand, (uint64_t)ptr * multiplicand));

  uint64_t accumulator = (uint64_t)ptr * multiplicand;
  uint64_t tmp = (uint64_t)(uintptr_t)bloom;
  return (uint32_t)__builtin_ia32_crc32di((uint64_t)accumulator, tmp);
}

/*
 * hash = crc32(ptr * multiplicand)
 */
static uint32_t vloom_hash_crc32mul128(const void *ptr, const uint8_t *bloom, uint64_t multiplicand, uint32_t __unused)
{
  unsigned __int128 tmp = (unsigned __int128)(uintptr_t)ptr * (unsigned __int128)multiplicand;
  return (uint32_t)__builtin_ia32_crc32di((uint64_t)(tmp >> 64), (uint64_t)tmp);
}

/**
 * Patches corresponding to above hash functions
 * hash = ptr + addend
 * */
static bool vloom_patch_add32(PatchInfo *info, const uint8_t *bloom, uint64_t __unused, uint32_t addend)
{
  static const uint8_t patch_rcx[] = {
      0x89, 0xf1,                        // mov %esi,%ecx
      0x81, 0xc1, 0x78, 0x56, 0x34, 0x12 // add $0x12345678,%ecx
  };
  const int CONST_SIZE_rcx = sizeof(patch_rcx);
  const int CONST_OFFSET_rcx = 4;

  static const uint8_t patch_r11[] = {
      0x41, 0x89, 0xf3,                        // mov %esi,%r11d
      0x41, 0x81, 0xc3, 0x78, 0x56, 0x34, 0x12 // add $0x12345678,%r11d
  };
  const int CONST_SIZE_r11 = sizeof(patch_r11);
  const int CONST_OFFSET_r11 = 6;

  /* patch selection */
  const uint8_t *patch;
  uint CONST_OFFSET;
  uint CONST_SIZE;
  switch (gnRegisterSet) {
  case RDXRDIRSI:
    patch = patch_rcx;
    CONST_OFFSET = CONST_OFFSET_rcx;
    CONST_SIZE = CONST_SIZE_rcx;
    break;
  case R11R10R9:
    patch = patch_r11;
    CONST_OFFSET = CONST_OFFSET_r11;
    CONST_SIZE = CONST_SIZE_r11;
    break;
  default:
    _UNREACHABLE;
    break;
  }

  uint8_t *ptr = info->pBuf;
  // assert (ptr != NULL)
  memcpy(ptr, patch, CONST_SIZE);
  memcpy(ptr + CONST_OFFSET, &addend, sizeof(addend));
  info->nBytes = CONST_SIZE;
  return true;
}

/**
 * Patches corresponding to above hash functions
 * hash = xor(ptr, addend)
 * */
static bool vloom_patch_xor32(PatchInfo *info, const uint8_t *bloom, uint64_t __unused, uint32_t addend)
{
  static const uint8_t patch_rcx[] = {
      0x48, 0x89, 0xf9,                  // mov %rdi,%rcx
      0x81, 0xf1, 0x78, 0x56, 0x34, 0x12 // xor $0x12345678,%ecx
  };
  const int CONST_SIZE_rcx = sizeof(patch_rcx);
  const int CONST_OFFSET_rcx = 5;

  static const uint8_t patch_r11[] = {
      0x49, 0x89, 0xfb,                        // mov %rdi,%r11
      0x41, 0x81, 0xf3, 0x78, 0x56, 0x34, 0x12 // xor $0x12345678,%r11d
  };
  const int CONST_SIZE_r11 = sizeof(patch_r11);
  const int CONST_OFFSET_r11 = 6;

  /* patch selection */
  const uint8_t *patch;
  uint CONST_OFFSET;
  uint CONST_SIZE;
  switch (gnRegisterSet) {
  case RDXRDIRSI:
    patch = patch_rcx;
    CONST_OFFSET = CONST_OFFSET_rcx;
    CONST_SIZE = CONST_SIZE_rcx;
    break;
  case R11R10R9:
    patch = patch_r11;
    CONST_OFFSET = CONST_OFFSET_r11;
    CONST_SIZE = CONST_SIZE_r11;
    break;
  default:
    _UNREACHABLE;
    break;
  }

  uint8_t *ptr = info->pBuf;
  // assert (ptr != NULL)
  memcpy(ptr, patch, CONST_SIZE);
  memcpy(ptr + CONST_OFFSET, &addend, sizeof(addend));
  info->nBytes = CONST_SIZE;
  return true;
}

// hash = crc32(accumulator, ptr)
static bool vloom_patch_crc32(PatchInfo *info, const uint8_t *bloom, uint64_t __unused, uint32_t accumulator)
{
  static const uint8_t patch_rcx[] = {
      0xB9, 0x78, 0x56, 0x34, 0x12,       // mov $0x0,%ecx
      0xF2, 0x48, 0x0F, 0x38, 0xF1, 0xCF, // crc32q %rdi,%rcx
  };
  const int CONST_SIZE_rcx = sizeof(patch_rcx);
  const int CONST_OFFSET_rcx = 1;

  static const uint8_t patch_r11[] = {
      0x41, 0xBB, 0x78, 0x56, 0x34, 0x12, // mov $0x0,%r11d
      0xF2, 0x4C, 0x0F, 0x38, 0xF1, 0xDF, // crc32q %rdi,%r11
  };
  const int CONST_SIZE_r11 = sizeof(patch_r11);
  const int CONST_OFFSET_r11 = 2;

  /* patch selection */
  const uint8_t *patch;
  uint CONST_OFFSET;
  uint CONST_SIZE;

  switch (gnRegisterSet) {
  case RDXRDIRSI:
    patch = patch_rcx;
    CONST_OFFSET = CONST_OFFSET_rcx;
    CONST_SIZE = CONST_SIZE_rcx;
    break;
  case R11R10R9:
    patch = patch_r11;
    CONST_OFFSET = CONST_OFFSET_r11;
    CONST_SIZE = CONST_SIZE_r11;
    break;
  default:
    _UNREACHABLE;
    break;
  }

  uint8_t *ptr = info->pBuf;
  // assert(ptr != NULL);
  memcpy(ptr, patch, CONST_SIZE);
  memcpy(ptr + CONST_OFFSET, &accumulator, sizeof(accumulator));
  info->nBytes = CONST_SIZE;
  return true;
}

// hash = ptr * multiplicand + addend
static bool vloom_patch_mul32(PatchInfo *info, const uint8_t *bloom, uint64_t multiplicand, uint32_t addend)
{
  static const uint8_t patch_rcx[] = {
      0x69, 0xCE, 0x78, 0x56, 0x34, 0x12, // imul $0x12345678,%esi,%ecx
  };
  const int CONST_SIZE_rcx = sizeof(patch_rcx);
  const int CONST_OFFSET_rcx_1 = 2;
  const int CONST_OFFSET_rcx_2 = 8;

  static const uint8_t patch_r11[] = {
      0x44, 0x69, 0xDE, 0x78, 0x56, 0x34, 0x12, // imul $0x12345678,%esi,%r11d
  };
  const int CONST_SIZE_r11 = sizeof(patch_r11);
  const int CONST_OFFSET_r11_1 = 3;
  const int CONST_OFFSET_r11_2 = 10;

  /* patch selection */
  const uint8_t *patch;
  uint CONST_OFFSET_1;
  uint CONST_OFFSET_2;
  uint CONST_SIZE;

  switch (gnRegisterSet) {
  case RDXRDIRSI:
    patch = patch_rcx;
    CONST_OFFSET_1 = CONST_OFFSET_rcx_1;
    CONST_OFFSET_2 = CONST_OFFSET_rcx_2;
    CONST_SIZE = CONST_SIZE_rcx;
    break;
  case R11R10R9:
    patch = patch_r11;
    CONST_OFFSET_1 = CONST_OFFSET_r11_1;
    CONST_OFFSET_2 = CONST_OFFSET_r11_2;
    CONST_SIZE = CONST_SIZE_r11;
    break;
  default:
    break;
  }

  uint8_t *ptr = info->pBuf;
  // assert (ptr != NULL)
  memcpy(ptr, patch, CONST_SIZE);
  uint32_t multiplicand32 = (uint32_t)multiplicand;
  memcpy(ptr + CONST_OFFSET_1, &multiplicand32, sizeof(multiplicand32));
  memcpy(ptr + CONST_OFFSET_2, &addend, sizeof(addend));
  info->nBytes = CONST_SIZE;

  return true;
}

// hash = crc32(bloom, ptr * multiplicand)
static bool vloom_patch_mul64crc32(PatchInfo *info, const uint8_t *bloom, uint64_t multiplicand, uint32_t unused)
{
  static const uint8_t patch_rcx[] = {
      0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs $0x0,%rcx
      0x48, 0x0F, 0xAF, 0xCF,                                     // imul   %rdi,%rcx
      0xF2, 0x48, 0x0F, 0x38, 0xF1, 0xCA                          // crc32q %rdx,%rcx
  };
  const int CONST_SIZE_rcx = sizeof(patch_rcx);
  const int CONST_OFFSET_rcx = 2;

  static const uint8_t patch_r11[] = {
      0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs $0x0,%r11
      0x4C, 0x0F, 0xAF, 0xDF,                                     // imul   %rdi,%r11
      0xF2, 0x4D, 0x0F, 0x38, 0xF1, 0xDA                          // crc32q %r10,%r11
  };
  const int CONST_SIZE_r11 = sizeof(patch_r11);
  const int CONST_OFFSET_r11 = 2;

  /* patch selection */
  const uint8_t *patch;
  uint CONST_OFFSET;
  uint CONST_SIZE;
  switch (gnRegisterSet) {
  case RDXRDIRSI:
    patch = patch_rcx;
    CONST_OFFSET = CONST_OFFSET_rcx;
    CONST_SIZE = CONST_SIZE_rcx;
    break;
  case R11R10R9:
    patch = patch_r11;
    CONST_OFFSET = CONST_OFFSET_r11;
    CONST_SIZE = CONST_SIZE_r11;
    break;
  default:
    _UNREACHABLE;
    break;
  }

  uint8_t *ptr = info->pBuf;
  // if (ptr != NULL)
  memcpy(ptr, patch, CONST_SIZE);
  memcpy(ptr + CONST_OFFSET, &multiplicand, sizeof(multiplicand));
  info->nBytes = CONST_SIZE;
  return true;
}

HPFUNCPAIR VLOOM_HPFuncMgr::HPPairs[] = /* escape clang-format */
    {
        {
            .pName = "add32", .fHash = vloom_hash_add32, .fPatch = vloom_patch_add32, .nRegs = 1, .bLoadBF = false,
            //  .b32Vtbl = true,
            //  .bComp = false,
            //  .nSize = vloom_patch_add32(NULL, NULL, 0, 0),
        },
        {
            .pName = "xor32", .fHash = vloom_hash_xor32, .fPatch = vloom_patch_xor32, .nRegs = 1, .bLoadBF = false,
            //      .b32Vtbl = true,
            //      .bComp = false,
            //      .nSize = vloom_patch_add32(NULL, NULL, 0, 0),
        },
        {
            .pName = "crc32", .fHash = vloom_hash_crc32, .fPatch = vloom_patch_crc32, .nRegs = 1, .bLoadBF = false,
            //  .b32Vtbl = false,
            //  .bComp = false,
            //  .nSize = vloom_patch_crc32(NULL, NULL, 0, 0),
        },
        {
            .pName = "mul32", .fHash = vloom_hash_mul32, .fPatch = vloom_patch_mul32, .nRegs = 1, .bLoadBF = false,
            //  .b32Vtbl = true,
            //  .bComp = true,
            //  .nSize = vloom_patch_mul32(NULL, NULL, 0, 0),
        },
        {
            .pName = "mul64crc32",
            .fHash = vloom_hash_mul64crc32,
            .fPatch = vloom_patch_mul64crc32,
            .nRegs = 2,
            .bLoadBF = true,
            //  .b32Vtbl = false,
            //  .bComp = true,
            //  .nSize = vloom_patch_mul64crc32(NULL, NULL, 0, 0),
        },
};

/**
 * error handler: prompt for the possible ones
 */
void VLOOM_HPFuncMgr::getFuncPrompt(const char *name)
{
#define MSG_EXPECT_FUNC "failed to find hash function %M\"%s\"%D; expected ones %M\"%s\"%D"
  size_t size = BUFSIZ;
  char buf[BUFSIZ];
  unsigned i, j;

  for (i = 0, j = 0; j < sizeof(HPPairs) / sizeof(HPFUNCPAIR); j++) {
    size_t len = strlen(HPPairs[j].pName);
    if (i + len + 3 >= size - 1)
      break;
    memcpy(buf + i, HPPairs[j].pName, len);
    memcpy(buf + i + len, ", ", 2);
    i += (len + 2);
  }

  if (i >= 3)
    buf[i - 2] = '\0';

  VLOOM_LOG(VLL_FATAL, MSG_EXPECT_FUNC, name, buf);
}

void VLOOM_HPFuncMgr::SetRegisterSet(bool bUseR11R10R9)
{
  if (bUseR11R10R9)
    gnRegisterSet = R11R10R9;
  else
    gnRegisterSet = RDXRDIRSI;
}

/* Retrive the function function according to its name */
HPFUNCPAIR *VLOOM_HPFuncMgr::GetFuncPair(const char *name)
{
  for (uint idx = 0; idx < sizeof(HPPairs) / sizeof(HPFUNCPAIR); idx++) {
    if (strcmp(HPPairs[idx].pName, name) == 0) // find the hash-func
      return &HPPairs[idx];
  }

  /* failed to find hash function */
  getFuncPrompt(name);

  return NULL;
}

/**
 * @names: Null-terminated string array
 * @conf: output, assume has enough memory
 * @return: the number of pairs
 */
HPFUNCPAIR **VLOOM_HPFuncMgr::SetFuncPairs(uint num, char *names[])
{
  HPFUNCPAIR **pairs = (HPFUNCPAIR **)calloc(num + 1, sizeof(HPFUNCPAIR *));
  char **name = names;
  uint tick;
  for (tick = 0; (tick < num) && (*name != NULL); tick++, name++)
    pairs[tick] = GetFuncPair(*name);

  return pairs;
}

void VLOOM_HPFuncMgr::visitFuncPair(PairVisitor &vtor)
{
  for (uint idx = 0; idx < sizeof(HPPairs) / sizeof(HPFUNCPAIR); idx++)
    vtor.visit(&HPPairs[idx]);
}