#define private public

#include "../hash.h"
#include "../mm.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(test_vloomhashpatch){};

extern char add32_patch_rdx[];
asm(".text\n\t"
    "add32_patch_rdx:\n\t"
    "mov %eax,%esi\n\t"
    "add $0x12345678,%esi\n\t");

extern char crc32_patch_rdx[];
asm(".text\n\t"
    "crc32_patch_rdx:\n\t"
    "mov $0x12345678,%esi\n\t"
    "crc32q %rax,%rsi\n\t");

extern char multiply32_patch_rdx[];
asm(".text\n\t"
    "multiply32_patch_rdx:\n\t"
    ".byte 0x69, 0xF0, 0x78, 0x56, 0x34, 0x12\n\t" // imul $0x12345678,%eax,%esi\n\t"
    "add $0x12345678,%esi\n\t");

extern char crc32mul64_v1_rdx[];
asm(".text\n\t"
    "crc32mul64_v1_rdx:\n\t"
    "movabs $0x12345678,%rdi\n\t "
    "imul   %rax,%rdi\n\t"
    "mov    %edx,%esi\n\t"
    "crc32q %rdi,%rsi");

extern char crc32mul64_v2_rdx[];
asm(".text\n\t"
    "crc32mul64_v2_rdx:\n\t"
    "movabs $0x12345678,%rdi\n\t "
    "imul   %rax,%rdi\n\t"
    "xor    %esi,%esi\n\t"
    "crc32q %rdi,%rsi");

const int LEN_add32_rdx = 8;
const int LEN_crc32_rdx = 11;
const int LEN_multiply32_rdx = 12;
const int LEN_crc32mul64_v1_rdx = 22;
const int LEN_crc32mul64_v2_rdx = 22;

extern char add32_patch_r11[];
asm(".text\n\t"
    "add32_patch_r11:\n\t"
    "mov %eax,%r10d\n\t"
    "add $0x12345678,%r10d\n\t");

extern char crc32_patch_r11[];
asm(".text\n\t"
    "crc32_patch_r11:\n\t"
    "mov $0x12345678,%r10d\n\t"
    "crc32q %rax,%r10\n\t");

extern char multiply32_patch_r11[];
asm(".text\n\t"
    "multiply32_patch_r11:\n\t"
    ".byte 0x44, 0x69, 0xD0, 0x78, 0x56, 0x34, 0x12\n\t" // imul $0x12345678,%eax,%esi\n\t"
    "add $0x12345678,%r10d\n\t");

extern char crc32mul64_v1_r11[];
asm(".text\n\t"
    "crc32mul64_v1_r11:\n\t"
    "movabs $0x12345678,%r9\n\t "
    "imul   %rax,%r9\n\t"
    "mov    %r11d,%r10d\n\t"
    "crc32q %r9,%r10");

extern char crc32mul64_v2_r11[];
asm(".text\n\t"
    "crc32mul64_v2_r11:\n\t"
    "movabs $0x12345678,%r9\n\t "
    "imul   %rax,%r9\n\t"
    "xor    %r10,%r10\n\t"
    "crc32q %r9,%r10");

const int LEN_add32_r11 = 10;
const int LEN_crc32_r11 = 12;
const int LEN_multiply32_r11 = 14;
const int LEN_crc32mul64_v1_r11 = 23;
const int LEN_crc32mul64_v2_r11 = 23;

/* global variables used in main_test() */
char *add32_patch = add32_patch_rdx;
char *crc32_patch = crc32_patch_rdx;
char *multiply32_patch = multiply32_patch_rdx;
char *crc32mul64_v1 = crc32mul64_v1_rdx;
char *crc32mul64_v2 = crc32mul64_v2_rdx;
int LEN_add32 = LEN_add32_rdx;
int LEN_crc32 = LEN_crc32_rdx;
int LEN_multiply32 = LEN_multiply32_rdx;
int LEN_crc32mul64_v1 = LEN_crc32mul64_v1_rdx;
int LEN_crc32mul64_v2 = LEN_crc32mul64_v2_rdx;

void main_test(void)
{
    using PairVisitor = VLOOM_HPFuncMgr::PairVisitor;

    class EchoInfo : public PairVisitor
    {
    public:
        bool visit(HPFUNCPAIR *pair)
        {
            // printf("%s\n", pair->name);
            CHECK_TRUE(pair->fHash != NULL);
            CHECK_TRUE(pair->fPatch != NULL);
            return true;
        }
    };

    VLOOM_HPFuncMgr *mgr = new VLOOM_HPFuncMgr();
    EchoInfo vtor;
    mgr->visitFuncPair(vtor);
    delete mgr;

    /* Check the patch size */
    HPFUNCPAIR *pair;
    uint8_t *ptr = (uint8_t *)malloc(128);
    const uint8_t *bloom = ptr;
    uint64_t __unused = 0x12345678;
    uint32_t addend = 0x12345678;

    // add32
    pair = VLOOM_HPFuncMgr::GetFuncPair("add32");
    pair->fPatch(ptr, bloom, __unused, addend);
    CHECK_EQUAL(LEN_add32, pair->nSize);
    CHECK_TRUE(memcmp(add32_patch, ptr, LEN_add32) == 0);

    // crc32
    pair = VLOOM_HPFuncMgr::GetFuncPair("crc32");
    pair->fPatch(ptr, bloom, __unused, addend);
    CHECK_EQUAL(LEN_crc32, pair->nSize);
    CHECK_TRUE(memcmp(crc32_patch, ptr, LEN_crc32) == 0);

    // multiply32
    pair = VLOOM_HPFuncMgr::GetFuncPair("multiply32");
    pair->fPatch(ptr, bloom, __unused, addend);
    CHECK_EQUAL(LEN_multiply32, pair->nSize);
    CHECK_TRUE(memcmp(multiply32_patch, ptr, LEN_multiply32) == 0);

    // crc32mul64_v1
    pair = VLOOM_HPFuncMgr::GetFuncPair("crc32mul64_v1");
    pair->fPatch(ptr, bloom, __unused, addend);
    CHECK_EQUAL(LEN_crc32mul64_v1, pair->nSize);
    CHECK_TRUE(memcmp(crc32mul64_v1, ptr, LEN_crc32mul64_v1) == 0);

    // crc32mul64_v2
    pair = VLOOM_HPFuncMgr::GetFuncPair("crc32mul64_v2");
    pair->fPatch(ptr, bloom, __unused, addend);
    CHECK_EQUAL(LEN_crc32mul64_v2, pair->nSize);
    CHECK_TRUE(memcmp(crc32mul64_v2, ptr, LEN_crc32mul64_v2) == 0);

    free(ptr);
}

TEST(test_vloomhashpatch, pairinfo)
{
    /* Use registesr set RDXRDIRSI */
    add32_patch = add32_patch_rdx;
    crc32_patch = crc32_patch_rdx;
    multiply32_patch = multiply32_patch_rdx;
    crc32mul64_v1 = crc32mul64_v1_rdx;
    crc32mul64_v2 = crc32mul64_v2_rdx;
    LEN_add32 = LEN_add32_rdx;
    LEN_crc32 = LEN_crc32_rdx;
    LEN_multiply32 = LEN_multiply32_rdx;
    LEN_crc32mul64_v1 = LEN_crc32mul64_v1_rdx;
    LEN_crc32mul64_v2 = LEN_crc32mul64_v2_rdx;
    VLOOM_HPFuncMgr::SetRegisterSet(1);
    main_test();

    /* Use registesr set R11R10R9 */
    add32_patch = add32_patch_r11;
    crc32_patch = crc32_patch_r11;
    multiply32_patch = multiply32_patch_r11;
    crc32mul64_v1 = crc32mul64_v1_r11;
    crc32mul64_v2 = crc32mul64_v2_r11;
    LEN_add32 = LEN_add32_r11;
    LEN_crc32 = LEN_crc32_r11;
    LEN_multiply32 = LEN_multiply32_r11;
    LEN_crc32mul64_v1 = LEN_crc32mul64_v1_r11;
    LEN_crc32mul64_v2 = LEN_crc32mul64_v2_r11;
    VLOOM_HPFuncMgr::SetRegisterSet(2);
    main_test();
}

int main(int ac, char **av)
{
    return CommandLineTestRunner::RunAllTests(ac, av);
}