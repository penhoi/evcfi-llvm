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

struct VLOOM_CHGCAST
{
    RB_ENTRY(VLOOM_CHGCAST)
    entry;
    VLOOM_CHGNODE *asIS;

    static int
    compare(const VLOOM_CHGCAST *a,
            const VLOOM_CHGCAST *b)
    {
        if (a->asIS == b->asIS)
            return 0;
        else
            return (a->asIS < b->asIS ? -1 : 1);
    }
};

RB_HEAD(VLOOM_UPCAST, VLOOM_CHGCAST);
RB_GENERATE(VLOOM_UPCAST, VLOOM_CHGCAST, entry, VLOOM_CHGCAST::compare);

struct VLOOM_CHGMAP_VPTR2NODE
{
    RB_ENTRY(VLOOM_CHGMAP_VPTR2NODE)
    entry;

    const void *vptr;      // The vptr
    VLOOM_CHGNODE *mytype; // The real type of current object
    uint32_t num_isAS;     // Total number of AS-IS types;
    VLOOM_UPCAST asIS;     // The used-as type of current object

    static int compare(const VLOOM_CHGMAP_VPTR2NODE *a, const VLOOM_CHGMAP_VPTR2NODE *b)
    {
        ulong pa = (ulong)a->vptr;
        ulong pb = (ulong)b->vptr;

        if (pa == pb)
            return 0;
        else
            return (pa < pb) ? -1 : 1;
    }
};

/* class hierachy graph: mapping from vptr to node */
RB_HEAD(VLOOM_CHGMAP, VLOOM_CHGMAP_VPTR2NODE);
RB_GENERATE(VLOOM_CHGMAP, VLOOM_CHGMAP_VPTR2NODE, entry, VLOOM_CHGMAP_VPTR2NODE::compare);

static VLOOM_CHGMAP chgmap = RB_INITIALIZER(&chgmap);

void *vloom_cha_chgmap_enquire(VLOOM_CHGMAP *chgmap, void *vtable_pointer);
void vloom_cha_chgmap_insert(void *data, VLOOM_CHGNODE *pnode, VLOOM_CHGEDGE *edge, VLOOM_CHGNODE *dnode);

TEST_GROUP(test_vloommap){

};

TEST(test_vloommap, chg_createmap)
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

    /* add another class */
    /* Class name */
    const char *tyname_derv = "_ZTV14nsXPTCStubBaseDerv";
    unsigned char vtable_derv[256];

    struct VLOOM_CHGNODE *node_derv = vloom_cha_add_vtable(tyname_derv, vtable_derv, 64);
    CHECK(node_derv != NULL);
    CHECK(node_derv->vtable_name != NULL);
    CHECK(node_derv->demangled != NULL);

    CHECK(node_derv->vtable.orign == vtable_derv);
    CHECK(node_derv->next_vtable == NULL);
    CHECK(node_derv->patches == NULL);

    /* this is used as a flag of new creating because of bad design */
    node_derv->next = node_derv;

    /* create edge */
    VLOOM_CHGEDGE *edge = (VLOOM_CHGEDGE *)vloom_mm_malloc(sizeof(VLOOM_CHGEDGE));

    edge->derived = node_derv;
    edge->offset = 0;

    /* Create mapping */
    vloom_cha_chgmap_insert(&chgmap, node, edge, node_derv);

    VLOOM_CHGMAP_VPTR2NODE *vptr2node = (VLOOM_CHGMAP_VPTR2NODE *)vloom_cha_chgmap_enquire(&chgmap, vtable_derv);
    CHECK(vptr2node != NULL);

    /* Add one more VTABLE to ... */
    unsigned char vtable_derv2[256];
    struct VLOOM_CHGNODE *node_derv2 = vloom_cha_add_vtable(tyname_derv, vtable_derv2, 64);
    CHECK(node_derv2 == node_derv);
    /* Create mapping */
    vloom_cha_chgmap_insert(&chgmap, node, edge, node_derv2);

    VLOOM_CHGMAP_VPTR2NODE *vptr2node2 = (VLOOM_CHGMAP_VPTR2NODE *)vloom_cha_chgmap_enquire(&chgmap, vtable_derv2);
    CHECK(vptr2node2 != NULL);
    CHECK(vptr2node2 != vptr2node);
}

#include <CppUTest/CommandLineTestRunner.h>

int main(int ac, char **av)
{
    return CommandLineTestRunner::RunAllTests(ac, av);
}
