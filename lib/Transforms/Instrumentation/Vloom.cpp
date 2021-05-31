#include <set>
#include <stdarg.h>
#include <stdio.h>
#include <vector>
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/TypeBuilder.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;
using namespace std;

static void encode_special_characters(std::string &str)
{
  struct Encode
  {
    const char *code;
    uint len;
    char s;
  };

  /* add new encodings if needs */
  Encode E[] = {{"DollaR", 6, '$'}, {"TidE", 4, '~'}, {nullptr, '\0', 0}};

  std::string::size_type pos;
  for (Encode *e = &E[0]; e->code; e++)
  {
    pos = 0u;
    while ((pos = str.find(e->s, pos)) != std::string::npos)
    {
      str.replace(pos, 1, e->code);
      pos += e->len;
    }
  }
}

// COMPATIBLE_MODE=1, POISON_MODE=2, FLAG_MODE=3, INVALID=etc
enum VLOOM_MODE
{
  VLOOM_COMP = 1,
  VLOOM_POIS = 2,
  VLOOM_FLAG = 3,
  VLOOM_TRACE = 4,
  VLOOM_IVLD,
};

#define SAN_TAG_STR "__VLOOM_SANITIZE_"
#define SAN_TAG_LEN strlen(SAN_TAG_STR)
#define PH_DELM_STR "_PH_"
#define PH_DELM_LEN strlen(PH_DELM_STR)

class VloomPass : public ModulePass
{
  static char ID;  // pass ID
  Module *thisMod; // current module

  bool VloomDisabled = false; // enabled by default
  unsigned mVloomMode = 1;
  unsigned mScratchRegset = 1;
  uint32_t mVloomSize = 64; // 64 bytes nop-sled
  uint32_t mScratchRegs = 3;
  uint32_t nVCallSeq;
  /* buffers used to do formating */
  char *szTempBuf;

  // Used for optimization, avoid duplicate Vptr checking.
  std::set<long> setVTables;

public:
  VloomPass() : ModulePass(ID), setVTables({})
  {
    szTempBuf = (char*)malloc(1024);
  }

  ~VloomPass() { free(szTempBuf); }
  void initVloom(Module &M);

  /* help functions */
  bool appendNops(std::string &str, unsigned size);
  char *mysprintf(const char *fmt, ...);
  const char *selectASMFlags(size_t nScratchRegs, bool bvcall);

  /* Do instrumentation for vcalls, and generate labels before CXXMehod calls */
  void handleCXXMethodCalls(Function &F, vector<Instruction *> &Dels);
  void instrumentVirtualCall(CallInst *C);
  void instrumentVirtualCall(InvokeInst *I);
  void _instrumentVirtualCall(Instruction *I, Function *callee, Value *VPtr);

  virtual bool runOnModule(Module &M)
  {
    // Get environment variables
    initVloom(M);

    // Exit if Vloom is disabled?
    if (VloomDisabled)
      return false; //  no changes

    if (getenv("VLOOM_PASS_DEBUG") != nullptr)
    {
      std::string outName(M.getName());
      outName += ".vloom.in.ll";
      std::error_code EC;
      llvm::raw_fd_ostream out(outName.c_str(), EC, llvm::sys::fs::F_None);
      M.print(out, nullptr);
    }

    /* Process CALL instructions */
    std::vector<Instruction *> DelFlagCalls;
    for (auto &F : M)
    {
      if (F.isDeclaration())
        continue;
      handleCXXMethodCalls(F, DelFlagCalls);
    }

    for (auto *I : DelFlagCalls)
      I->eraseFromParent();

    return true;
  }
};

char VloomPass::ID = 0;

namespace llvm
{
  ModulePass *createVloomPass() { return new VloomPass(); }
} // namespace llvm

/* copy from ItaniumCXXABI.cpp */
void VloomPass::initVloom(Module &M)
{
  thisMod = &M;

  const char *vstr = getenv("VLOOM_DISABLED");
  if ((vstr != NULL) && (strncmp(vstr, "1", 2) == 0))
    VloomDisabled = true;

  vstr = getenv("VLOOM_MODE");
  if (vstr != NULL)
    mVloomMode = atoi(vstr);

  vstr = getenv("VLOOM_REGSET");
  if (vstr != NULL)
    mScratchRegset = atoi(vstr);
  assert(mScratchRegset == 1 || mScratchRegset == 2);

  vstr = getenv("VLOOM_SIZE");
  if (vstr != NULL)
    mVloomSize = atoi(vstr);
  assert(mVloomSize >= 8 && mVloomSize < 256);

  vstr = getenv("VLOOM_SCRATCH");
  if (vstr != NULL)
    mScratchRegs = atoi(vstr);
  assert(mScratchRegs <= 3);

  vstr = getenv("VLOOM_DEBUGLABEL");
  if ((vstr != NULL) && (strncmp(vstr, "1", 2) == 0))
    srandom(0x70000);
  else
    srandom((uint)time(NULL));
  nVCallSeq = random() & 0x0FFFFFFF;
}

/* Append nop instructions into asmStr */
bool VloomPass::appendNops(std::string &asmStr, unsigned nops)
{
  while (nops >= 8)
  {
    asmStr += ".byte 0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00\n";
    nops -= 8;
  }
  while (nops >= 4)
  {
    asmStr += ".byte 0x0F,0x1F,0x40,0x00\n";
    nops -= 4;
  }
  while (nops >= 2)
  {
    asmStr += ".byte 0x66,0x90\n";
    nops -= 2;
  }
  while (nops >= 1)
  {
    asmStr += ".byte 0x90\n";
    nops -= 1;
  }
  return true;
}

/* A simple wrapper of sprintf */
char *VloomPass::mysprintf(const char *fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  vsprintf(szTempBuf, fmt, va);
  va_end(va);
  return szTempBuf;
}

/**
 * @brief Process each CALL instruction
 *
 * @param F
 * @param Dels Some CALL instructions are used as flags, they would be removed
 */
void VloomPass::handleCXXMethodCalls(Function &F, vector<Instruction *> &Dels)
{
  setVTables.clear();
  for (Function::iterator BN = F.begin(), BE = F.end(); BN != BE; BN++)
  {
    BasicBlock &BB = *BN;
    for (BasicBlock::iterator IN = BB.begin(), IE = BB.end(); IN != IE; IN++)
    {
      /* We only care about InvokeInst and CallInst */
      Function *callee = nullptr;
      InvokeInst *I = nullptr;
      CallInst *C = nullptr;
      bool bCallBase = false;
      switch (IN->getOpcode())
      {
      default:
        bCallBase = false;
        break;
      case Instruction::Call:
        C = dyn_cast<CallInst>(IN);
        callee = C->getCalledFunction();
        bCallBase = true;
        break;
      case Instruction::Invoke:
        I = dyn_cast<InvokeInst>(IN);
        callee = I->getCalledFunction();
        bCallBase = true;
        break;
      }
      if (!bCallBase || callee == nullptr || !callee->hasName())
        continue;

      StringRef name = callee->getName();
      // A flag CALL instruction?
      if (name.startswith(SAN_TAG_STR))
      {
        if (C)
          instrumentVirtualCall(C);
        else
          instrumentVirtualCall(I);

        Dels.push_back(&*IN);
      }
    }
  }
}

const char *VloomPass::selectASMFlags(size_t nScratchRegs, bool bVcall)
{
  static const char *GPRSR_flags[2][4] = {
      {
          "{rdi},~{dirflag},~{fpsr},~{flags}",
          "{rdi},~{rcx},~{dirflag},~{fpsr},~{flags}",
          "{rdi},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags}",
          "{rdi},~{rcx},~{rdx},~{rsi},~{dirflag},~{fpsr},~{flags}",
      },
      {
          "={rdi},{rdi},~{dirflag},~{fpsr},~{flags}",
          "={rdi},{rdi},~{rcx},~{dirflag},~{fpsr},~{flags}",
          "={rdi},{rdi},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags}",
          "={rdi},{rdi},~{rcx},~{rdx},~{rsi},~{dirflag},~{fpsr},~{flags}",
      }};

  static const char *GPRNR_flags[2][4] = {
      {
          "{rdi},~{dirflag},~{fpsr},~{flags}",
          "{rdi},~{r11},~{dirflag},~{fpsr},~{flags}",
          "{rdi},~{r11},~{r10},~{dirflag},~{fpsr},~{flags}",
          "{rdi},~{r11},~{r10},~{r9},~{dirflag},~{fpsr},~{flags}",
      },
      {
          "={rdi},{rdi},~{dirflag},~{fpsr},~{flags}",
          "={rdi},{rdi},~{r11},~{dirflag},~{fpsr},~{flags}",
          "={rdi},{rdi},~{r11},~{r10},~{dirflag},~{fpsr},~{flags}",
          "={rdi},{rdi},~{r11},~{r10},~{r9},~{dirflag},~{fpsr},~{flags}",
      }};


  uint idx = bVcall ? 1 : 0;
  const char *(*arr)[2][4], *asmFlags;

  switch (mScratchRegset)
  {
  case 1:
    arr = &GPRSR_flags;
    break;
  case 2:
    arr = &GPRNR_flags;
    break;
  default:
    asm("int3");
    break;
  }

  switch (mVloomMode)
  {
  case VLOOM_FLAG:
  case VLOOM_TRACE:
    asmFlags = (*arr)[idx][0];
    break;

  default:
    asmFlags = (*arr)[idx][nScratchRegs];
    break;
  }
  return asmFlags;
}

/**
 * @brief Instrument assembly code before a virtual call
 *
 * @param Call A CALL instruction used as a flag, would be replaced
 * @param F
 * @param info return some information
 */

void VloomPass::instrumentVirtualCall(CallInst *C)
{
  Function *callee = C->getCalledFunction();
  Value *VPtr = C->getArgOperand(0);
  _instrumentVirtualCall(C, callee, VPtr);
}

void VloomPass::instrumentVirtualCall(InvokeInst *I)
{
  Function *callee = I->getCalledFunction();
  Value *VPtr = I->getArgOperand(0);
  _instrumentVirtualCall(I, callee, VPtr);
}

void VloomPass::_instrumentVirtualCall(Instruction *I, Function *callee, Value *VPtr)
{
  // Agressive optimization: in a function check VTable once only
  long hash = (long)VPtr->getType();
  hash += VPtr->getRawSubclassOptionalData();
  hash += VPtr->getValueID();
  if (setVTables.find(hash) == setVTables.end())
    setVTables.insert(hash);
  else
    return;

  // Extract information from
  StringRef infoStr = callee->getName();
  SmallVector<StringRef, 2> vecFS;
  infoStr.split(vecFS, PH_DELM_STR);
  assert(vecFS.size() == 2);
  std::string strClassName = vecFS[1];
  ulong nNopSize = mVloomSize;
  ulong nRegNum = mScratchRegs;

  std::string strType = strClassName;
  std::string symStr = mysprintf("__VLOOM_VCALL_S%d_R%d", nNopSize, nRegNum);

  // symStr += "_I";
  // symStr += std::to_string(VTableIndex);
  symStr += "_V";
  symStr += strType;
  symStr += mysprintf("_PH_%d", nVCallSeq++);

  std::string asmStr;
  asmStr += ".weak ";
  asmStr += symStr;
  asmStr += "\n";
  //FIX: encode dollar symbol
  encode_special_characters(asmStr);

  // Pad with NOPs.  This means the binary can be executed without
  // VLOOM instrumentaton; albeit with a performance penalty.
  char szNops[64];
  unsigned nops;

  switch (mVloomMode)
  {
  case VLOOM_FLAG:
    nRegNum = 0;
    nNopSize = 8; // sizeof("ud2\nint3\nud2\nint3\n") + short-jump
    nops = 0;
    break;

  case VLOOM_TRACE:
    nRegNum = 0;
    nNopSize = 13; // 8+5
    nops = 5;      // encoding inside a move instruction
    break;

  default:
    // min_size = 8;
    nops = nNopSize - 8; // sizeof("ud2\nint3\nud2\nint3\n") + short-jump
    break;
  }

  const char *szPoison = "ud2\nint3\nud2\nint3\n";
  const char *jmpFmt = ".byte 0xEB,0x%x\n";

  switch (mVloomMode)
  {
  case VLOOM_COMP: // COMPATIBLE_MODE
  case VLOOM_FLAG: // FLAG_MODE
  case VLOOM_TRACE:
    asmStr += mysprintf(jmpFmt, nNopSize - 2); // Jump over nops
    asmStr += szPoison;                        // add poison flag
    break;

  case VLOOM_POIS:                             // POISON_MODE
    asmStr += szPoison;                        // add poison flag
    asmStr += mysprintf(jmpFmt, nNopSize - 8); // Jump over nops
    break;

  default:
    asm("int3");
    break;
  }

  // output config information: nRegNum : VLOOM_REGSTER_SET:
  // VLOOM_SIDE_EFFECT
  if (nops >= 5)
  {
    const char *encodeFmt = ".byte 0xb8, %2d, %2d, %2d, %2d\n";
    switch (mVloomMode)
    {
    case VLOOM_TRACE:
      *(unsigned *)(szNops + 32) = rand();
      sprintf(szNops, encodeFmt, szNops[32], szNops[33], szNops[34],
              szNops[35]);
      break;

    default:
      sprintf(szNops, encodeFmt, mVloomMode, mScratchRegset, nRegNum, nNopSize);
      break;
    }
    asmStr += szNops;
    nops -= 5;
  }

  // append nop instructions
  appendNops(asmStr, nops);

  switch (mVloomMode) {
  default:
    break;
  case VLOOM_COMP:
  case VLOOM_POIS:
    // asmStr += ".byte 0xEB,0x08\n"; // Jump over symStr
    // asmStr += ".quad 0x06eb + "; // 8 bytes in total
    // asmStr += symStr;          // export the location of this call-site
    asmStr += "\n" + symStr + ":\n";
    break;
  }

  // Full checking scheme
  // IRBuilder<> B(I);
  // llvm::FunctionType *AsmTy =
  //     llvm::FunctionType::get(VPtr->getType(), {VPtr->getType()}, false);
  // const char *asmFlags = selectASMFlags(nRegNum, true);
  // auto *AsmFunc = llvm::InlineAsm::get(AsmTy, asmStr, asmFlags, false);
  // VPtr = B.CreateCall(AsmFunc, {VPtr});
  // I->replaceAllUsesWith(VPtr);

  // Optimization scheme
  IRBuilder<> B(I);
  llvm::FunctionType *AsmTy =
      llvm::FunctionType::get(B.getVoidTy(), {VPtr->getType()}, false);
  const char *asmFlags = selectASMFlags(nRegNum, false); // false
  auto *AsmFunc = llvm::InlineAsm::get(AsmTy, asmStr, asmFlags, false);
  B.CreateCall(AsmFunc, {VPtr});
}
