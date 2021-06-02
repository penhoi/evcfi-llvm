#ifndef _TEST_VLOOM_CFG_H__
#define _TEST_VLOOM_CFG_H__

#include "../tree.h"

struct VLOOM_CHGNODE;
struct VLOOM_CHGEDGE;
struct VLOOM_DERIVATION;
struct VLOOM_PATCH_ENTRY;

#define VLOOM_MAX_K 16

struct VLOOM_CONFIG
{
    unsigned k;                 // Total hash functions.
    bool use32;                 // Relocate VTABLEs?
    bool compress;              // Compress masks?
    bool blank;                 // Blank parameters after use.
    bool bloom32;               // Use 32bit BLOOM filter.
    unsigned regs;              // Number of scratch registers.
    unsigned truncate;          // Index truncation.
    unsigned hash[VLOOM_MAX_K]; // Hash functions.
};

struct VLOOM_HASH_PARAM
{
    uint64_t param64; // 64bit hash parameter
    uint32_t param32; // 32bit hash parameter
};

struct VLOOM_PATCH_ENTRY
{
    unsigned size;
    unsigned regs;
    void *addr;
    VLOOM_PATCH_ENTRY *next;
};

struct VLOOM_FILE_ENTRY
{
    RB_ENTRY(VLOOM_FILE_ENTRY)
    entry;
    const char *filename;

    static int compare(const VLOOM_FILE_ENTRY *a, const VLOOM_FILE_ENTRY *b)
    {
        return strcmp(a->filename, b->filename);
    }
};

RB_HEAD(VLOOM_FILE_TABLE, VLOOM_FILE_ENTRY);

struct VLOOM_CHGEDGE
{
    RB_ENTRY(VLOOM_CHGEDGE)
    entry;
    size_t offset;
    VLOOM_CHGNODE *derived;

    static int compare(const VLOOM_CHGEDGE *a, const VLOOM_CHGEDGE *b)
    {
        if (a->derived == b->derived)
        {
            if (a->offset == b->offset)
                return 0;
            else
                return (a->offset < b->offset ? -1 : 1);
        }
        else
        {
            return (a->derived < b->derived ? -1 : 1);
        }
    }
};

RB_HEAD(VLOOM_DERIVATION, VLOOM_CHGEDGE);

struct VLOOM_CHGNODE
{
#define VLOOM_VTALBE_MINADDR 0x10000
#define VLOOM_VTALBE_MAXMAPPING 4
    struct VTABLE_ADDR
    {
        void *orign; // VTABLE location
        void *clone; // 32bit cloned VTABLE location
        size_t size; // table size in bytes
    };

    RB_ENTRY(VLOOM_CHGNODE)
    entry;

    VLOOM_CHGNODE *next;     // Next in set (optional)
    const char *vtable_name; // VTABLE name
    const char *demangled;   // Demangled VTABLE name

    VTABLE_ADDR vtable;       // The VTABLE mapped with the class name
    VTABLE_ADDR *next_vtable; // default to NULL, or VTABLE_ADDRINFO[VTALBE_MAXMAPPING]

    VLOOM_DERIVATION derived; // All derived classes.
    size_t num_derived;       // Number of derived classes.

    VLOOM_PATCH_ENTRY *patches; // All patch locations.

    bool vcall; // Used by a virtual call?
    bool bloom; // Entries added to BLOOM filter?

    VLOOM_HASH_PARAM params[]; // Random hash parameters.

    static int
    compare(const VLOOM_CHGNODE *a, const VLOOM_CHGNODE *b)
    {
        return strcmp(a->vtable_name, b->vtable_name);
    }
};

struct VLOOM_PRIVATE_INFO
{
    VLOOM_CONFIG conf;      // configuration
    VLOOM_FILE_TABLE files; // All loaded files.
    uint8_t *bloom;         // Location of the bloom filter.
};

#endif //#ifndef _TEST_VLOOM_CFG_H__
