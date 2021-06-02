#ifndef _UTILTS_H__
#define _UTILTS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef uint32_t
typedef unsigned int uint32_t;
#endif // !uint32_t

/* useful defines */
#define VLOOM_PAGE_SIZE 4096
#define VLOOM_PAGES_SIZE(size) ((((size)-1) / VLOOM_PAGE_SIZE) * VLOOM_PAGE_SIZE + VLOOM_PAGE_SIZE)

#define VLOOM_PAGES_BASE(offset) ((uint8_t *)(offset) - (uintptr_t)(offset) % VLOOM_PAGE_SIZE)

#define PAGE_SIZE 0x1000
#define ROUND_DW_PAGESZ(val) (((val) >> 12) << 12)
#define ROUND_UP_PAGESZ(val) ROUND_DW_PAGESZ(val + PAGE_SIZE - 1)

#define VLOOM_MAXVAL(a, b) ((a) < (b) ? (b) : (a))
#define VLOOM_MINVAL(a, b) ((a) < (b) ? (a) : (b))

#define VLOOM_MIN_CODEADDR 0x10000

/* creat Key-Value paris */
struct KVPAIR {
  char *K, *V;
  KVPAIR(const char *key, const char *val);
  ~KVPAIR();
};

struct INTCMPTOR {
  bool operator()(const size_t lhs, const size_t rhs) const { return lhs < rhs; }
};

/* compare-tor, used to initialize the std:map<char*, typename, STRCMPTOR>
 * template */
struct STRCMPTOR {
  bool operator()(const char *lhs, const char *rhs) const { return (strcmp(lhs, rhs) < 0); }
};

char *utils_strdup(const char *s);
char *utils_trimwhitespace(char *str);
char *utils_trimcomment(char *szLine);
uint32_t utils_hashstrs(const char *str);
size_t utils_hashstrs(const char *s1, const char *s2);

#define BLOOM_HASH_NUM 16
#endif //_UTILTS_H__