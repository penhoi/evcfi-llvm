#include <CppUTest/TestHarness.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vloom_func.h"
#include "vloom_chg.h"

TEST_GROUP(test_vloomchg){

};

TEST(test_vloomchg, chg_createnode)
{
    /* Class name */
    const char *tyname = "_ZTV14nsXPTCStubBase";
    unsigned char vtable[256];

    struct VLOOM_CHGNODE *node = vloom_cha_add_vtable(tyname, vtable, 64);
    CHECK(node != NULL);
    CHECK(node->vtable_name != NULL);
    STRCMP_CONTAINS(node->vtable_name, tyname);
    CHECK(node->demangled != NULL);
    STRCMP_CONTAINS(node->demangled, node->vtable_name);

    CHECK(node->vtable.orign == vtable);
    CHECK(node->next_vtable == NULL);
    CHECK(node->patches == NULL);

    /* this is used as a flag because of bad design */
    node->next = node;

    /* add another vtable for the same class name */
    unsigned char vtable_next[256];
    struct VLOOM_CHGNODE *node_next = vloom_cha_add_vtable(tyname, vtable_next, 64);
    CHECK(node_next == node);
    CHECK(node->next_vtable != NULL);
    CHECK(node->next_vtable[0].orign == vtable_next);
    CHECK(node->next_vtable[1].orign == NULL);

    /* add one more vtable */
    unsigned char vtable_next_next[256];
    struct VLOOM_CHGNODE *node_next_next = vloom_cha_add_vtable(tyname, vtable_next_next, 64);
    CHECK(node_next_next == node);
    CHECK(node->next_vtable != NULL);
    CHECK(node->next_vtable[1].orign == vtable_next_next);
}

TEST(test_vloomchg, chg_derivation)
{
    /* _ZTVN7mozilla12SprintfStateINS_17MallocAllocPolicyEEE */

    char const *base = "MallocAllocPolicy";
    char const *derv = "mozilla12SprintfState";

    vloom_cha_add_derivation(base, derv, 0);

    VLOOM_CHGNODE *base_entry = vloom_cha_chgraph_lookup(base);
    VLOOM_CHGNODE *derv_entry = vloom_cha_chgraph_lookup(derv);

    CHECK(base_entry->derived.rbh_root != NULL);
    CHECK(base_entry->num_derived == 1);
    CHECK(derv_entry->derived.rbh_root == NULL);
    CHECK(derv_entry->num_derived == 0);
}

#include <CppUTest/CommandLineTestRunner.h>

int main(int ac, char **av)
{
    return CommandLineTestRunner::RunAllTests(ac, av);
}
