#ifndef _VLOOM_LOGGING_H__
#define _VLOOM_LOGGING_H__

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

/****************************************************************************/
/* VLOOM LOGGING SYSTEM                                                     */
/****************************************************************************/
enum VLOOM_LOG_LEVEL {
  VLL_TRACE = 0,   // find one part of a function specifically
  VLL_DEBUG = 1,   // diagnostically helpful
  VLL_INFO = 2,    // useful information to log
  VLL_WARN = 3,    // potentially cause application oddities
  VLL_ERROR = 4,   // Any error which is fatal to the operation
  VLL_VCFIBUG = 5, // The target problem has VCFI-violation
  VLL_FATAL = 6,   // Any error that is forcing a shutdown
  VLL_RESULT = 7,  // log result
};

/* initialize the logging system */
struct EnvConfig;
void vloom_LogInit(EnvConfig *tEnv);
void vloom_LogFini(void);

/* logging the execpution of libvloom.so */
void vloom_log_logging(int level, const char *format, ...);

#ifdef VLOOM_UTEST

/* utest_printf supports colorized format */
#include "./unit_test/printf.h"
#define VLOOM_LOG(level, format, ...) utest_printf(format, ##__VA_ARGS__)

#else

extern int VLOOM_LOGLEVEL;
#define VLOOM_LOG(level, format, ...)                  \
  do {                                                 \
    if ((int)level >= VLOOM_LOGLEVEL)                  \
      vloom_log_logging(level, format, ##__VA_ARGS__); \
  } while (false)

#endif

#ifdef DEBUG
#define _UNREACHABLE asm("int3")
#else
#define _UNREACHABLE asm("ud2")
#endif // DEBUG

/* Log the execution of patched hash-functions */
long vloom_vcallsite_hook(const ulong *mask, const ulong vptr);

#endif //#define _VLOOM_LOGGING_H__
