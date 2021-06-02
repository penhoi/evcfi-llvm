/**
 * @file elfmgr.h
 * @author your name (you@domain.com)
 * @brief CHA, VLOOM, and ElfModuleMgr is organized as foodie-hunter-chef modle
 * VLOOM hunters new files, and then ask ElfModuleMgr to cook it; the output is feed to CHA.
 * @version 0.1
 * @date 2021-01-27
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef _VLOOM_ELF_H__
#define _VLOOM_ELF_H__
#include "logging.h"
#include "tree.h"
#include "utils.h"
#include <libelf.h>
#include <map>

/* Save info of an elf symbol */
struct ElfSymb {
  Elf64_Addr value; /* Symbol value: st_value + info->offset */
  Elf64_Xword size; /* Symbol size: size = st_size */
  char name[];      /* C style symbol name */
};

class ELFFileInfo;

struct ElfRela {
  Elf64_Addr value; /* Relocation address: r_offset + info->offset */
  char name[];      /* C style symbol name */
};

struct SEGMENT_INFO {
  SEGMENT_INFO *prev, *next; // Next segement of the same file
  ELFFileInfo *file;         // points to the file
  const uint8_t *base;
  size_t size;
  int prot;
};

struct FILE_INFO {
  ELFFileInfo *file;
  long handler;
  int status;

  enum FILE_STATUS {
    ELFS_NOENTRY = 0,             // no such file
    ELFS_OPENED = 1,              // This file is managed by an FILE_ENTRY
    ELFS_NOINFO = 2,              // no symbols and relocation entries
    ELFS_HASINFO = 3,             // has symbols and relocation entries
    ELFS_ANLYZED = 4,             // all classed have been CHAed;
    ELFS_SEG_LOADED = (1ul << 1), // all segments already loaded;
    ELFS_SEC_PARSED = (1ul << 2), // all sections have been parsed;

    // ELFS_UNMAPED = (1ul << 4),    // This file is unmapped from memory;
  };

  void setStatus(int stat) { status |= (1 << stat); }
  int getStatus() { return status; }
  bool testStatus(int stat) { return (status & (1 << stat)) != 0; }
};

/*
 * Manage the main program and all dynamilcally linked/opened libraries.
 */
class SymbolFilter;
class ReloctFilter;
class ELFFileInfo;
struct CHGNODE;
class MemMgr;
class ElfModuleMgr {

  friend ELFFileInfo;

public:
  /* Segment information. */
  struct SEGMENT_ENTRY {
    RB_ENTRY(SEGMENT_ENTRY) entry;
    SEGMENT_INFO *seg;
    long base, end; // for quick search

    static int compare(const SEGMENT_ENTRY *a, const SEGMENT_ENTRY *b)
    {
#define MSG_OVERLAP "overlapping segments detected (%p..%p vs %p..%p)"
      if ((a->base < b->base) && (a->end <= b->base))
        return -1;
      if ((b->base < a->base) && (b->end <= a->base))
        return 1;
      VLOOM_LOG(VLL_INFO, MSG_OVERLAP, a->base, a->end, b->base, b->end);
      return 0;
    }
  };

private:
  RB_HEAD(SEGMENTS, SEGMENT_ENTRY);
  RB_GENERATE(SEGMENTS, SEGMENT_ENTRY, entry, SEGMENT_ENTRY::compare);
  SEGMENTS mSegments = {nullptr};

public:
  struct FILE_ENTRY {
    RB_ENTRY(FILE_ENTRY) entry;
    FILE_INFO fi;

    static int compare(const FILE_ENTRY *a, const FILE_ENTRY *b)
    {
      if (a->fi.handler == b->fi.handler)
        return 0;
      else
        return (a->fi.handler < b->fi.handler) ? -1 : 1;
    }
  };

private:
  // maps file name to handler
  std::map<long, const char *> m_mapHandler2Name;
  RB_HEAD(FILES, FILE_ENTRY);
  RB_GENERATE(FILES, FILE_ENTRY, entry, FILE_ENTRY::compare);
  // static FILES Files;
  FILES Files = {nullptr};

public:
  ElfModuleMgr();
  ~ElfModuleMgr();

  /* extending the dlopen/dlclose operation with metadata for management */
  FILE_INFO *dlopenExt(const char *file_name, ptrdiff_t offset, SymbolFilter *sf = nullptr,
                       ReloctFilter *rf = nullptr);
  // void dlcloseExt(const char *file_name);
  void dlcloseExt(const char *file_name)
  {
    uint32_t handler = utils_hashstrs(file_name);
    removeFile(handler);
  }
  void dlcloseExt(FILE_INFO *info) { removeFile(info->handler); }

  /* These interfaces can be used by external code for convinence */
  FILE_INFO *lookupFile(const char *file_name);

  /* remove file-entry */
  void removeFile(const char *name);
  void removeFile(FILE_INFO *info) { removeFile(info->handler); }

  /* count how many files have been dlopened */
  int getFileNum(void);

  /* functions for collect relocation entries */
  typedef std::map<const char *, ElfSymb *, STRCMPTOR> MAPSYMB;
  typedef std::map<Elf64_Addr, ElfRela *> MAPRELA;
  MAPSYMB *getElfSymbols(const char *file_name);
  MAPSYMB *getElfSymbols(FILE_INFO *fi);
  MAPRELA *getElfRelocts(const char *file_name);
  MAPRELA *getElfRelocts(FILE_INFO *fi);

  /* for querying segment information */
  SEGMENT_INFO *lookupSegment(const void *addr);
  bool loadElfSegments(FILE_INFO *fi);
  void unloadElfSegments(FILE_INFO *fi);

  /* count how many segments have been loaded */
  int getSegmentNum(void);

  void relocateVtables(FILE_INFO *info, CHGNODE *node);

private:
  /* Lookup if the file is already under management */
  FILE_ENTRY *lookupFile(long file_handler)
  {
    FILE_ENTRY *entry;
    FILE_ENTRY key;

    key.fi.handler = (long)file_handler;
    entry = FILES_RB_FIND(&Files, &key);
    return entry;
  }

  /* add an file-entry for a file */
  FILE_ENTRY *addFile(ELFFileInfo *info, long file_handler)
  {
    FILE_ENTRY *newentry = (FILE_ENTRY *)malloc(sizeof(FILE_ENTRY));
    newentry->fi.file = info;
    newentry->fi.handler = file_handler;
    newentry->fi.status = 0;
    FILES_RB_INSERT(&Files, newentry);

    return newentry;
  }

  /* remove file-entry */
  void removeFile(long file_handler);

  /* function for loading/unloading PT_LOAD segments */
  bool loadElfSegments(FILE_INFO &info);
  void unloadElfSegments(FILE_INFO &info);

  SEGMENT_ENTRY *lookupSegmentEntry(const void *addr);
  SEGMENT_ENTRY *addSegmentEntry(SEGMENT_INFO *seg);
  void delSegmentEntry(SEGMENT_INFO *seg);
};

/* Base class of ELF analyzer, organized as a chain of analyzer */
class SymbolFilter {
protected:
  SymbolFilter *m_next;

public:
  SymbolFilter() : m_next(nullptr) {}
  virtual bool doFilter(const char *str) { return true; }
};

class ReloctFilter {
protected:
  ReloctFilter *m_next;

public:
  ReloctFilter() : m_next(nullptr) {}
  virtual bool doFilter(const char *str) { return true; }
};
#endif // _VLOOM_ELF_H__