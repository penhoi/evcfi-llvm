#ifndef __TEST_DEFINES_H__
#define __TEST_DEFINES_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "vloom_chg.h"

/****************************************************************************/
/* VLOOM MALLOC                                                             */
/****************************************************************************/
void *vloom_mm_malloc(size_t size);
char *vloom_mm_strdup(const char *str);

/****************************************************************************/
/* VLOOM RANDOM                                                             */
/****************************************************************************/
uint64_t vloom_rand_int64(void);
uint32_t vloom_rand_int32(void);
void vloom_rand_buffer(void *buf_0, size_t len);

/****************************************************************************/
/* VLOOM CHA                                                             */
/****************************************************************************/
VLOOM_CHGNODE *vloom_cha_chgraph_lookup(const char *name);
VLOOM_CHGNODE *vloom_cha_add_vtable(const char *symbol_name, void *vtable, size_t size);
void vloom_cha_add_derivation(const char *base, const char *derived, size_t vptr_oft);

#endif //#ifndef __TEST_DEFINES_H__
