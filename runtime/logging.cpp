/**
 * The logging system
 */
#include "logging.h"
#include "config.h"
#include <assert.h>
#include <cxxabi.h>   // for __cxa_demangle
#include <dlfcn.h>    // for dladdr
#include <execinfo.h> // for backtrace
#include <sstream>
#include <stdarg.h>
#include <unistd.h>

FILE *VLOOM_LOGFILE = NULL;
int VLOOM_LOGLEVEL = VLL_ERROR;
bool LOG_PATCH_EXECUTION = false;

/****************************************************************************/
/* VLOOM DEBUGGING & LOG MESSAGES                                           */
/****************************************************************************/
/*
 * Colorize a format string.
 */
static const char *vloom_log_colorize(int fd, const char *format, char *buf, ssize_t size)
{
  bool colorize = (isatty(fd) != 0);
  size_t i, j;
  for (i = 0, j = 0; format[i] != '\0' && i < size - 2 && j < size - 2; i++) {
    if (format[i] != '%') {
      buf[j++] = format[i];
      continue;
    }
    const char *code;
    switch (format[i + 1]) {
    case 'R':
      code = "31";
      break;
    case 'G':
      code = "32";
      break;
    case 'B':
      code = "34";
      break;
    case 'Y':
      code = "33";
      break;
    case 'M':
      code = "35";
      break;
    case 'C':
      code = "36";
      break;
    case 'D':
      code = "0";
      break;
      break;
    default:
      buf[j++] = format[i];
      continue;
    }
    i++;
    if (!colorize)
      continue;
    if (j >= size - 10)
      break;
    buf[j++] = '\33';
    buf[j++] = '[';
    buf[j++] = code[0];
    if (code[1] != '\0')
      buf[j++] = code[1];
    buf[j++] = 'm';
  }
  buf[j++] = '\0';
  return buf;
}

/* This function produces a stack backtrace with demangled function & method names. */
static void vloom_log_backtrace_xxx(int level = 100, int skip = 2)
{
#define MAX_STACK_FRAME 128
  void *callstack[MAX_STACK_FRAME];
  int nMaxFrames;
  char buf[1024];

  if ((level + skip) < MAX_STACK_FRAME)
    nMaxFrames = level + skip;
  else
    nMaxFrames = MAX_STACK_FRAME;

  int nFrames = backtrace(callstack, nMaxFrames);
  char **symbols = backtrace_symbols(callstack, nFrames);

  std::ostringstream trace_buf;
  for (int i = skip; i < nFrames; i++) {
    Dl_info info;
    if (dladdr(callstack[i], &info)) {
      char *demangled = NULL;
      int status;
      demangled = abi::__cxa_demangle(info.dli_sname, NULL, 0, &status);
      snprintf(buf, sizeof(buf), "%-3d %p %s + %zd\n", i, callstack[i], status == 0 ? demangled : info.dli_sname,
               (char *)callstack[i] - (char *)info.dli_saddr);
      free(demangled);
    }
    else {
      snprintf(buf, sizeof(buf), "%-3d %p\n", i, callstack[i]);
    }
    trace_buf << buf;

    snprintf(buf, sizeof(buf), "%s\n", symbols[i]);
    trace_buf << buf;
  }
  free(symbols);
  if (nFrames == nMaxFrames)
    trace_buf << "[truncated]\n";

  fprintf(VLOOM_LOGFILE, "%s\n", trace_buf.str().c_str());
}

static void vloom_log_backtrace(int level = 100, int skip = 2)
{
  if (VLOOM_LOGFILE == NULL)
    return;

#define MAX_TRACE 256
  void *trace[MAX_TRACE];
  int nMaxFrames;

  if ((level + skip) < MAX_TRACE)
    nMaxFrames = level + skip;
  else
    nMaxFrames = MAX_TRACE;

  int len = backtrace(trace, nMaxFrames);
  char **trace_strs = backtrace_symbols(trace, len);

  for (int i = skip; i < len; i++) {
    fprintf(VLOOM_LOGFILE, "%d: %s\n", i, trace_strs[i]);
  }
  if (len == 0 || len == MAX_TRACE)
    fprintf(VLOOM_LOGFILE, "...\n");
}

/*
 * Print an error and abort.
 */
static __attribute__((__noreturn__)) void vloom_log_fatalerror(const char *format, va_list ap)
{
  if (VLOOM_LOGFILE == NULL)
    VLOOM_LOGFILE = stderr;

  if (isatty(fileno(VLOOM_LOGFILE)))
    fprintf(VLOOM_LOGFILE, "\33[31mVLOOM FATAL ERROR\33[0m: ");
  else
    fprintf(VLOOM_LOGFILE, "VLOOM FATAL ERROR: ");

  char buf[BUFSIZ];

  format = vloom_log_colorize(fileno(VLOOM_LOGFILE), format, buf, sizeof(buf));
  vfprintf(VLOOM_LOGFILE, format, ap);
  putc('\n', VLOOM_LOGFILE);

  vloom_log_backtrace();
  _UNREACHABLE;
  exit(-1);
}

/*
 * Print a warning.
 */
static void vloom_log_vcfibug(const char *format, va_list ap)
{
  assert(VLOOM_LOGFILE != NULL);

  FILE *stream = VLOOM_LOGFILE;

  if (isatty(fileno(stream)))
    fprintf(stream, "\33[33mVLOOM VCFIBUG\33[0m: ");
  else
    fprintf(stream, "VLOOM VCFIBUG: ");

  char buf[BUFSIZ];

  format = vloom_log_colorize(fileno(stream), format, buf, sizeof(buf));
  vfprintf(stream, format, ap);
  putc('\n', stream);
}

/*
 * Print a warning.
 */
static void vloom_log_error(const char *format, va_list ap)
{
  assert(VLOOM_LOGFILE != NULL);

  FILE *stream = VLOOM_LOGFILE;

  if (isatty(fileno(stream)))
    fprintf(stream, "\33[33mVLOOM ERROR\33[0m: ");
  else
    fprintf(stream, "VLOOM ERROR: ");

  char buf[BUFSIZ];

  format = vloom_log_colorize(fileno(stream), format, buf, sizeof(buf));
  vfprintf(stream, format, ap);
  putc('\n', stream);
}
/*
 * Print a warning.
 */
static void vloom_log_warning(const char *format, va_list ap)
{
  assert(VLOOM_LOGFILE != NULL);

  FILE *stream = VLOOM_LOGFILE;

  if (isatty(fileno(stream)))
    fprintf(stream, "\33[33mVLOOM WARNING\33[0m: ");
  else
    fprintf(stream, "VLOOM WARNING: ");

  char buf[BUFSIZ];

  format = vloom_log_colorize(fileno(stream), format, buf, sizeof(buf));
  vfprintf(stream, format, ap);
  putc('\n', stream);
}

/*
 * Print a warning.
 */
static void vloom_log_information(const char *format, va_list ap)
{
  assert(VLOOM_LOGFILE != NULL);

  FILE *stream = VLOOM_LOGFILE;

  if (isatty(fileno(stream)))
    fprintf(stream, "\33[33mVLOOM INFO\33[0m: ");
  else
    fprintf(stream, "VLOOM INFO: ");

  char buf[BUFSIZ];

  format = vloom_log_colorize(fileno(stream), format, buf, sizeof(buf));
  vfprintf(stream, format, ap);
  putc('\n', stream);
}

/*
 * Print a debug message.
 */
static void vloom_log_debug(const char *format, va_list ap)
{
  if (VLOOM_LOGFILE == NULL)
    return;

  if (isatty(fileno(VLOOM_LOGFILE)))
    fprintf(VLOOM_LOGFILE, "\33[36mVLOOM DEBUG\33[0m: ");
  else
    fprintf(VLOOM_LOGFILE, "VLOOM DEBUG: ");

  char buf[BUFSIZ];

  format = vloom_log_colorize(fileno(VLOOM_LOGFILE), format, buf, sizeof(buf));
  vfprintf(VLOOM_LOGFILE, format, ap);
  putc('\n', VLOOM_LOGFILE);
}

static void vloom_log_trace(const char *format, va_list ap)
{
  if (VLOOM_LOGFILE == NULL)
    return;

  if (isatty(fileno(VLOOM_LOGFILE)))
    fprintf(VLOOM_LOGFILE, "\33[36mVLOOM TRACE\33[0m: ");
  else
    fprintf(VLOOM_LOGFILE, "VLOOM TRACE: ");

  char buf[BUFSIZ];

  format = vloom_log_colorize(fileno(VLOOM_LOGFILE), format, buf, sizeof(buf));
  vfprintf(VLOOM_LOGFILE, format, ap);
  putc('\n', VLOOM_LOGFILE);
}

void vloom_log_logging(int level, const char *format, ...)
{
  va_list ap;
  va_start(ap, format);

  switch (level) {
  case VLL_TRACE:
    vloom_log_trace(format, ap);
    break;

  case VLL_DEBUG:
    vloom_log_debug(format, ap);
    break;

  case VLL_INFO:
    vloom_log_information(format, ap);
    break;

  case VLL_WARN:
    vloom_log_warning(format, ap);
    break;

  case VLL_ERROR:
    vloom_log_error(format, ap);
    break;

  case VLL_VCFIBUG:
    vloom_log_vcfibug(format, ap);
    break;

  case VLL_FATAL:
    vloom_log_fatalerror(format, ap);
    break;

  case VLL_RESULT:
  default:
    vloom_log_trace(format, ap);
    break;
  }

  va_end(ap);
}

/* Logging system should execute before all the others */
void __attribute__((constructor(101))) vloom_LogInit0(void)
{
  VLOOM_LOGFILE = stdout;     // log to stdout
  VLOOM_LOGLEVEL = VLL_ERROR; // only log errors
  VLOOM_LOG(VLL_TRACE, "......%s......", __FUNCTION__);
}

void __attribute__((destructor(101))) vloom_LogFini0(void)
{
  VLOOM_LOGFILE = stdout;     // log to stdout
  VLOOM_LOGLEVEL = VLL_ERROR; // only log errors
  VLOOM_LOG(VLL_TRACE, "......%s......", __FUNCTION__);
}

void vloom_LogInit(EnvConfig *tEnv)
{
  VLOOM_LOG(VLL_TRACE, "Initialize the logging system");
  // Read configuration
  const char *fname = tEnv->szLogFile;

  if (fname != NULL) {
    if (strcasecmp(fname, "stderr") == 0)
      VLOOM_LOGFILE = stderr;
    else if (strcasecmp(fname, "stdout") == 0)
      VLOOM_LOGFILE = stdout;
    else
      VLOOM_LOGFILE = fopen(fname, "w+");
  }
  else {
    char strFName[1024] = {0}; // log file
    sprintf(strFName, "%d.log", getpid());
    VLOOM_LOGFILE = fopen(strFName, "w+");
  }
  assert(VLOOM_LOGFILE != NULL);

  /* log level: [debug = 0, debugging, warning = 2, warn, fatal = 4] */
  if (tEnv->nLogLevel < VLL_TRACE)
    VLOOM_LOGLEVEL = VLL_TRACE;
  else if (tEnv->nLogLevel > VLL_FATAL)
    VLOOM_LOGLEVEL = VLL_FATAL;
  else
    VLOOM_LOGLEVEL = tEnv->nLogLevel;

  /* log the patching code */
  LOG_PATCH_EXECUTION = true;
}

/* Restore the status set by vloom_LogInit0 */
void vloom_LogFini(void)
{
  if (VLOOM_LOGFILE != NULL && !isatty(fileno(VLOOM_LOGFILE))) {
    fclose(VLOOM_LOGFILE);
    VLOOM_LOGFILE = stdout;
  }
  VLOOM_LOG(VLL_TRACE, "Finalize the logging system");
}

/* Apply this function to log the execution of patches */
/* please add -fno-stack-protector to avoid RCX being clobberred,
 * otherwise to modify the patch code to save and restore RCX */
long vloom_vcallsite_hook(const ulong *mask, const ulong vptr)
{
  /*__cdecl doesn't work, so we write inline assembly code */
  /** Note that the caller also save several registers.
   * We just make this function to have a minimal change to registers.
   * All changed registers are preseved by the caller.
   */
  unsigned long regs[20];
  unsigned long top;

  asm("_saveall:\n\t"
      "lea %[pr], %%rax\n\t"
      "add $16*8, %%rax\n\t"
      "xchg %%rsp, %%rax\n\t"

      "push %%rdi\n\t"
      "push %%rsi\n\t"
      "push %%rdx\n\t"
      "push %%rcx\n\t"
      // "push %%rax\n\t"
      "push %%rbx\n\t"
      "push %%r8\n\t"
      "push %%r9\n\t"
      "push %%r10\n\t"
      "push %%r11\n\t"
      "push %%r12\n\t"
      "push %%r13\n\t"
      "push %%r14\n\t"
      "push %%r15\n\t"

      "xchg %%rsp, %%rax\n\t"
      "mov %%rax, %[top]\n\t"
      : [top] "=m"(top)
      : [pr] "m"(regs));

  /* Do a lot of logging stuff */
  if (vptr != (*mask & vptr)) {
    // VLOOM_LOG(VLL_WARN, "ERROR: [@%p] is mask: 0x%08lx; vptr:0x%lx", mask, *mask, vptr);
    // vloom_cha_chgmap_enquire_wrapper((void *)vptr);
  }
  asm("_popall:\n\t"
      "mov %[top], %%rax\n\t"
      "xchg %%rsp, %%rax\n\t"

      "pop %%r15\n\t"
      "pop %%r14\n\t"
      "pop %%r13\n\t"
      "pop %%r12\n\t"
      "pop %%r11\n\t"
      "pop %%r10\n\t"
      "pop %%r9\n\t"
      "pop %%r8\n\t"
      "pop %%rbx\n\t"
      // "pop %%rax\n\t"
      "pop %%rcx\n\t"
      "pop %%rdx\n\t"
      "pop %%rsi\n\t"
      "pop %%rdi\n\t"
      "xchg %%rsp, %%rax\n\t"
      :
      : [top] "m"(top));
  // return (mask & vptr);
  return vptr;
}
