#include "elfmgr.h"
#include "cha.h"
#include "logging.h"
#include "mm.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

typedef std::map<const char *, ElfSymb *, STRCMPTOR> MAPSYMB;
typedef std::map<Elf64_Addr, ElfRela *> MAPRELA;

/*--------------------------- A single ELF_FILE ----------------------------*/
class ELFFileInfo {
  friend ElfModuleMgr;

  ElfModuleMgr *m_ElfMgr;
  char *m_FileName;   // file name
  ptrdiff_t m_Offset; // offset returned by dlmap_link

  Elf *m_ELF; // ELF object return by elf_xxx
  int m_FD;   // File descriptor returned by open()

  /* loadable segments of this file */
  SEGMENT_INFO m_lstSegs;
  /* sections used to parse symbols and reloc-entries */
  struct SEC_INFO {
    const char *strtab;
    size_t stridx;
    size_t strtabSize;
    const char *dynstr;
    size_t dynstrSize;
    Elf64_Sym *symtab;
    size_t symtabSize;
    Elf64_Sym *dynsym;
    size_t dynsymSize;
    Elf64_Rela *relatab;
    size_t relatabSize;
  } m_SECs;

  /* symbols and relocatable-entries used for enforcing VCFI */
  MAPSYMB *m_mapSymbs;
  MAPRELA *m_mapRelas;

  SymbolFilter *m_SFilter;
  ReloctFilter *m_RFilter;

public:
  ELFFileInfo(ElfModuleMgr *mgr, const char *file_name, ptrdiff_t offset);
  ~ELFFileInfo();

  /* functions for collect relocation entries */
  bool collectSymbolReloct(SymbolFilter *sf = nullptr, ReloctFilter *rf = nullptr);
  MAPSYMB *getElfSymbols() { return m_mapSymbs; }
  MAPRELA *getElfRelocts() { return m_mapRelas; }
  // void relocateVtables(ELFFileInfo *info, CHGNODE *node);

  // SEGMENT_INFO *lookupSegment(const void *askfor);
  bool loadSegments();
  void unloadSegments();

private:
  bool mapSymStrSections();
  void unmapSymStrSections();
  bool decodeElfString(size_t strtab_idx, std::string &res, bool dyn = false);

  bool collectElfSymbols();
  bool collectElfRelocts();

  /* parse and add a new segment */
  SEGMENT_INFO *parseAddSegment(Elf64_Phdr *phdr);
  void removeSegment(SEGMENT_INFO *seg);
};

ELFFileInfo::ELFFileInfo(ElfModuleMgr *mgr, const char *file_name, ptrdiff_t offset)
    : m_ElfMgr(mgr), m_Offset(offset), m_SECs()
{
  m_FileName = strdup(file_name);
  m_mapSymbs = new MAPSYMB();
  m_mapRelas = new MAPRELA();
  m_lstSegs.prev = m_lstSegs.next = &m_lstSegs;
}

ELFFileInfo::~ELFFileInfo()
{
  assert(m_mapSymbs != NULL);
  for (const auto &pair : *m_mapSymbs) {
    ElfSymb *sym = pair.second;
    free(sym);
  }
  delete m_mapSymbs;

  assert(m_mapRelas != NULL);
  for (auto &pair : *m_mapRelas) {
    ElfRela *rela = pair.second;
    free(rela);
  }
  delete m_mapRelas;

  /* delete all of its segments */
  unloadSegments();
}

bool ELFFileInfo::collectSymbolReloct(SymbolFilter *sf, ReloctFilter *rf)
{
  // if (info.stat & ELFS_SEC_PARSED) // already collected ?
  //   return true;
  m_SFilter = sf;
  m_RFilter = rf;

  /* initialize libelf ? */
  VLOOM_LOG(VLL_TRACE, "initialize libelf");
  if (elf_version(EV_CURRENT) == EV_NONE) {
    VLOOM_LOG(VLL_FATAL, "failed to initialize ELF: %s", elf_errmsg(-1));
    return false;
  }

  int fd = m_FD = open(m_FileName, O_RDONLY);
  if (fd < 0) {
#define ERR_OPEN "failed to open ELF file \"%s\": %s"
    VLOOM_LOG(VLL_TRACE, ERR_OPEN, m_FileName, strerror(errno));
    return false;
  }

  Elf *elf = m_ELF = elf_begin(fd, ELF_C_READ, NULL);
  if (elf == NULL) {
#define MSG_PARSE "failed to parse ELF file \"%s\": %s"
    VLOOM_LOG(VLL_TRACE, MSG_PARSE, m_FileName, elf_errmsg(-1));
    return false;
  }

  bool bRet = false;
  if (mapSymStrSections()) {
    bRet = collectElfSymbols();
    bRet |= collectElfRelocts();
  }
  unmapSymStrSections();

  elf_end(elf);
  close(fd);

  return bRet;
}

/*
 * Map a ELF section into memory.
 */
static void *mapSection(Elf64_Shdr *shdr, int fd, size_t *size_ptr)
{
  off_t offset = (off_t)VLOOM_PAGES_BASE((void *)shdr->sh_offset);
  size_t segSize = shdr->sh_size + shdr->sh_offset;
  size_t size = VLOOM_PAGES_SIZE(segSize - offset);

#define MSG_MAPPING "mapping section at offsets %zd..%zd (%zd..%zd)"
  VLOOM_LOG(VLL_TRACE, MSG_MAPPING, shdr->sh_offset, segSize, offset, offset + size);
  void *ptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
  if (ptr == MAP_FAILED) {
#define ERR_MAP "failed to map ELF section into memory: %s"
    VLOOM_LOG(VLL_ERROR, ERR_MAP, strerror(errno));
  }

  ptr = (uint8_t *)ptr + (shdr->sh_offset - offset);
  if (size_ptr != NULL)
    *size_ptr = shdr->sh_size;
  return ptr;
}

/*
 * Unmap a section from memory.
 */
static void unmapSection(void *ptr, size_t size)
{
  if (ptr == NULL)
    return;

  uint8_t *base = (uint8_t *)VLOOM_PAGES_BASE(ptr);
  size += (uint8_t *)ptr - base;
  if (munmap(base, size) < 0) {
#define MSG_FAIL_UNMAP "failed to unmap ELF section from memory: %s"
    VLOOM_LOG(VLL_ERROR, MSG_FAIL_UNMAP, strerror(errno));
  }
}

/* map symbol & string sections for CHAing & patching */
bool ELFFileInfo::mapSymStrSections()
{
  const char *filename = m_FileName;
  int fd = m_FD;

  if (elf_getshdrstrndx(m_ELF, &m_SECs.stridx) != 0) {
#define ERR_GETSHDR "failed to get section index for ELF file \"%s\": %s"
    VLOOM_LOG(VLL_FATAL, ERR_GETSHDR, filename, elf_errmsg(-1));
  }
  Elf_Scn *scn = NULL;
  Elf64_Shdr *shdr;
  while ((scn = elf_nextscn(m_ELF, scn)) != NULL) {
    const char *name = NULL;

    if ((shdr = elf64_getshdr(scn)) == NULL)
      continue;

    switch (shdr->sh_type) {
    case SHT_DYNSYM:
#define FATAL_MULDYN "failed to load multiple dynamic symbol tables for \"%s\""
      if (m_SECs.dynsym != NULL)
        VLOOM_LOG(VLL_FATAL, FATAL_MULDYN, filename);

      m_SECs.dynsym = (Elf64_Sym *)mapSection(shdr, fd, &m_SECs.dynsymSize);
      break;

    case SHT_SYMTAB:
#define FATAL_MULSYM "failed to load multiple symbol tables  for \"%s\""
      if (m_SECs.symtab != NULL)
        VLOOM_LOG(VLL_FATAL, FATAL_MULSYM, filename);
      m_SECs.symtab = (Elf64_Sym *)mapSection(shdr, fd, &m_SECs.symtabSize);
      break;

    case SHT_STRTAB:
#define FATAL_MULSTR "failed to load multiple string tables for \"%s\""
      name = elf_strptr(m_ELF, m_SECs.stridx, shdr->sh_name);
      if (strcmp(name, ".strtab") == 0) {
        if (m_SECs.strtab != NULL)
          VLOOM_LOG(VLL_FATAL, FATAL_MULSTR, filename);
        m_SECs.strtab = (const char *)mapSection(shdr, fd, &m_SECs.strtabSize);
      }
      else if (strcmp(name, ".dynstr") == 0) {
        if (m_SECs.dynstr != NULL)
          VLOOM_LOG(VLL_FATAL, FATAL_MULSTR, filename);
        m_SECs.dynstr = (const char *)mapSection(shdr, fd, &m_SECs.dynstrSize);
      }
      break;

    case SHT_RELA:
#define FATAL_MULRELA "failed to load multiple relocation tables for \"%s\""
      name = elf_strptr(m_ELF, m_SECs.stridx, shdr->sh_name);
      if (strcmp(name, ".rela.text") == 0) {
        if (m_SECs.relatab != NULL)
          VLOOM_LOG(VLL_FATAL, FATAL_MULRELA, filename);
        m_SECs.relatab = (Elf64_Rela *)mapSection(shdr, fd, &m_SECs.relatabSize);
      }
      break;

    default:
      break;
    }
  }
  if (m_SECs.symtab == NULL) {
#define MSG_NOSYM "failed to load symbol table for \"%s\" (is the file stripped?)"
    VLOOM_LOG(VLL_TRACE, MSG_NOSYM, filename);
    return false;
  }
  if (m_SECs.strtab == NULL) {
#define MSG_NOSTR "failed to load string table for \"%s\""
    VLOOM_LOG(VLL_TRACE, MSG_NOSTR, filename);
    return false;
  }
  VLOOM_LOG(VLL_TRACE, "found string table at address %p", m_SECs.strtab);
  VLOOM_LOG(VLL_TRACE, "found symbol table at address %p", m_SECs.symtab);

  return true;
}

/*
 * Clean up an info.
 */
void ELFFileInfo::unmapSymStrSections()
{
  if (m_SECs.dynsym != NULL) {
    VLOOM_LOG(VLL_TRACE, "unmapping string table at address %p", m_SECs.dynsym);
    unmapSection((void *)m_SECs.dynsym, m_SECs.dynsymSize);
  }
  if (m_SECs.symtab != NULL) {
    VLOOM_LOG(VLL_TRACE, "unmapping symbol table at address %p", m_SECs.symtab);
    unmapSection(m_SECs.symtab, m_SECs.symtabSize);
  }
  if (m_SECs.strtab != NULL) {
    VLOOM_LOG(VLL_TRACE, "unmapping string table at address %p", m_SECs.strtab);
    unmapSection((void *)m_SECs.strtab, m_SECs.strtabSize);
  }
  if (m_SECs.dynstr != NULL) {
    VLOOM_LOG(VLL_TRACE, "unmapping symbol table at address %p", m_SECs.dynstr);
    unmapSection((void *)m_SECs.dynstr, m_SECs.dynstrSize);
  }

  if (m_SECs.relatab != NULL) {
    VLOOM_LOG(VLL_TRACE, "unmapping relocation table at address %p", m_SECs.relatab);
    unmapSection(m_SECs.relatab, m_SECs.relatabSize);
  }
}

/* collect all kinds of strings from ELF file */
bool ELFFileInfo::collectElfSymbols()
{
  VLOOM_LOG(VLL_TRACE, "Collect symbols from file %s", m_FileName);

  assert((m_mapSymbs != NULL) && (m_mapSymbs->size() == 0));
  std::string xStr; // for crossing procedure using
  for (size_t symoft = 0, i = 0; symoft < m_SECs.symtabSize; symoft += sizeof(Elf64_Sym), i++) {
    Elf64_Sym *sym = m_SECs.symtab + i;

    bool bSucc = decodeElfString(sym->st_name, xStr);
    const char *symName = xStr.c_str();

    if (!bSucc || (symName[0] == '\0'))
      continue;

    if (m_SFilter != NULL && !m_SFilter->doFilter(symName))
      continue;

    if (m_mapSymbs->find(symName) != m_mapSymbs->end())
      continue;

    if (strncmp(symName, "__VLOOM_VCALL", 13) == 0 && sym->st_value == 0)
      continue;

    VLOOM_LOG(VLL_TRACE, "Find symbols %s", symName);
    size_t size = sizeof(ElfSymb) + strlen(symName) + 1;
    size = ((size + 3) >> 2) << 2; // 4 bytes align
    ElfSymb *newSym = (ElfSymb *)malloc(size);
    newSym->size = sym->st_size;
    newSym->value = sym->st_value + m_Offset;
    strcpy(newSym->name, symName);
    m_mapSymbs->insert({newSym->name, newSym});
  }
  return true;
}

/* collect all kinds of strings from ELF file */
bool ELFFileInfo::collectElfRelocts()
{
  VLOOM_LOG(VLL_TRACE, "Collect relocation entries from file %s", m_FileName);
  assert((m_mapRelas != NULL) && (m_mapRelas->size() == 0));

  std::string xStr; // for crossing procedure using
  for (size_t i = 0; i * sizeof(Elf64_Rela) < m_SECs.relatabSize; i++) {
    Elf64_Rela *rela = m_SECs.relatab + i;
    if (ELF64_R_TYPE(rela->r_info) != R_X86_64_64)
      continue;
    Elf64_Sym *sym = m_SECs.symtab + ELF64_R_SYM(rela->r_info);

    bool bSucc = decodeElfString(sym->st_name, xStr);
    const char *symName = xStr.c_str();
    if (!bSucc)
      continue;

    VLOOM_LOG(VLL_TRACE, "Find relocation entry for %s", symName);
    ElfRela *newRela = (ElfRela *)malloc(sizeof(ElfRela) + strlen(symName) + 4);
    newRela->value = rela->r_offset + m_Offset;
    strcpy(newRela->name, symName);
    m_mapRelas->insert({newRela->value, newRela});
  }
  return true;
}

/* Decode some special characters that encoded by LLVM */
struct CharacterEncoder {
  const char *s;
  uint n;
  char c;
};
static CharacterEncoder LLVMCODER[] = {{"DollaR", 6, '$'}, {"TidE", 4, '~'}, {nullptr, '\0', 0}};

static void decode_special_characters(std::string &str)
{
  std::string::size_type pos;
  for (CharacterEncoder *e = &LLVMCODER[0]; e->s; e++) {
    pos = 0u;
    while ((pos = str.find(e->s, pos)) != std::string::npos) {
      str.replace(pos, e->n, e->s);
      pos += e->n;
    }
  }
}

/*
 * Get a string name.
 */
bool ELFFileInfo::decodeElfString(size_t strtab_idx, std::string &res, bool dyn)
{
  const char *str = nullptr;

  if (strtab_idx != 0) {
    if (!dyn) {
      if (!(strtab_idx >= m_SECs.strtabSize))
        str = m_SECs.strtab + strtab_idx;
    }
    else {
      if (!(m_SECs.dynstr == NULL || strtab_idx >= m_SECs.dynstrSize))
        str = m_SECs.dynstr + strtab_idx;
    }
  }
  if (str != NULL) {
    res = str;
    decode_special_characters(res);
  }
  return (str != nullptr);
}

static int check_seg_overlap(const SEGMENT_INFO *a, const SEGMENT_INFO *b)
{
#define MSG_OVERLAP "overlapping segments detected (%p..%p vs %p..%p)"
  if ((a->base < b->base) && (a->base + a->size <= b->base))
    return -1;
  if ((b->base < a->base) && (b->base + b->size <= a->base))
    return 1;
  VLOOM_LOG(VLL_INFO, MSG_OVERLAP, a->base, a->base + a->size, b->base, b->base + b->size);
  return 0;
}

/*
 * Get the memory permissions.
 */
// SEGMENT_INFO *ELFFileInfo::lookupSegment(const void *askfor) {

//   const uint8_t *addr = (const uint8_t *)askfor;
//   for (SEGMENT_INFO *seg = m_lstSegs.next; seg->next != &m_lstSegs;
//        seg = seg->next) {
//     if ((seg->base <= addr) && (addr < seg->base + seg->size))
//       return seg;
//   }

//   return nullptr;
// }

/*
 * Record a new memory segment.
 */
SEGMENT_INFO *ELFFileInfo::parseAddSegment(Elf64_Phdr *phdr)
{
  if (phdr->p_memsz == 0 || phdr->p_type != PT_LOAD)
    return NULL;

  const uint8_t *base = (const uint8_t *)phdr->p_vaddr + m_Offset;
  const uint8_t *end = base + (size_t)phdr->p_memsz;
  int prot = ((phdr->p_flags & PF_R) != 0 ? PROT_READ : 0) | ((phdr->p_flags & PF_W) != 0 ? PROT_WRITE : 0) |
             ((phdr->p_flags & PF_X) != 0 ? PROT_EXEC : 0);

  // Find all overlapping segments:
  SEGMENT_INFO key;
  key.base = base;
  key.size = (size_t)phdr->p_memsz;

  SEGMENT_INFO *ovseg = m_lstSegs.next;
  bool bMorePass = true;
  while (bMorePass && (ovseg != &m_lstSegs)) {
    /* a new pass */
    while (ovseg) {
      bool bOV = check_seg_overlap(ovseg, &key);

      if (!bOV) {
        bMorePass = false;
        break;
      }

      SEGMENT_INFO &seg = *ovseg;
      prot |= seg.prot;
      if (seg.base < base)
        base = seg.base;
      if (seg.base + seg.size > end)
        end = seg.base + seg.size;

      removeSegment(ovseg);
    } // while (ovseg)

    SEGMENT_INFO *ovseg = m_lstSegs.next;
  } // while (bMorePass xxx)

  SEGMENT_INFO *newSeg = (SEGMENT_INFO *)malloc(sizeof(SEGMENT_INFO));
  SEGMENT_INFO &seg = *newSeg;
  seg.file = this;
  seg.base = base;
  seg.size = end - base;
  seg.prot = prot;
  seg.prev = m_lstSegs.prev;
  seg.next = &m_lstSegs;
  m_lstSegs.prev = newSeg;

#define MSG_ADDSEG                                                                                                    \
  "add segment with address range %p..%p (%zu) with protections (%c%c%c) "                                            \
  "from file \"%s\""
  VLOOM_LOG(VLL_TRACE, MSG_ADDSEG, seg.base, seg.base + seg.size, seg.size, ((seg.prot & PROT_READ) != 0 ? 'r' : '-'),
            ((seg.prot & PROT_WRITE) != 0 ? 'w' : '-'), ((seg.prot & PROT_EXEC) != 0 ? 'x' : '-'), m_FileName);

  if (phdr->p_type == PT_GNU_RELRO) {
#define MSG_RELRO "fixing PT_GNU_RELRO segment %p..%p (%zu)"
#define FATAL_MPROT "failed to set page protections for segment: %s"
    VLOOM_LOG(VLL_TRACE, MSG_RELRO, seg.base, seg.base + seg.size, seg.size);
    uint8_t *ptr = VLOOM_PAGES_BASE(seg.base);

    if (mprotect(ptr, seg.size + (seg.base - ptr), seg.prot | PROT_WRITE) < 0)
      VLOOM_LOG(VLL_FATAL, FATAL_MPROT, strerror(errno));
  }

  return newSeg;
}

void ELFFileInfo::removeSegment(SEGMENT_INFO *seg)
{

  if (seg == &m_lstSegs)
    return;

  seg->prev->next = seg->next;
  seg->next->prev = seg->prev;
  free(seg);
}

bool ELFFileInfo::loadSegments()
{
  const char *filename = m_FileName;

  /* initialize libelf ? */
  VLOOM_LOG(VLL_TRACE, "initialize libelf");
  if (elf_version(EV_CURRENT) == EV_NONE) {
    VLOOM_LOG(VLL_FATAL, "failed to initialize ELF: %s", elf_errmsg(-1));
    return false;
  }

  int fd = m_FD = open(m_FileName, O_RDONLY);
  if (fd < 0) {
#define ERR_OPEN "failed to open ELF file \"%s\": %s"
    VLOOM_LOG(VLL_TRACE, ERR_OPEN, m_FileName, strerror(errno));
    return false;
  }

  Elf *elf = m_ELF = elf_begin(fd, ELF_C_READ, NULL);
  if (elf == NULL) {
#define MSG_PARSE "failed to parse ELF file \"%s\": %s"
    VLOOM_LOG(VLL_TRACE, MSG_PARSE, m_FileName, elf_errmsg(-1));
    return false;
  }

  // Record all segments:
  size_t num_phdrs;
  if (elf_getphdrnum(elf, &num_phdrs) < 0) {
#define ERR_GETPHDR "failed to get number of program headers for ELF file \"%s\": %s"
    VLOOM_LOG(VLL_FATAL, ERR_GETPHDR, filename, elf_errmsg(-1));
  }

  Elf64_Phdr *phdr = elf64_getphdr(elf);
  for (size_t i = 0; i < num_phdrs; i++) {
    parseAddSegment(&phdr[i]);
  }

  close(fd);
  elf_end(elf);

  /* notify file manager to remove segment entries */
  SEGMENT_INFO *seg = m_lstSegs.next;
  while (seg != &m_lstSegs)
    m_ElfMgr->addSegmentEntry(seg);

  return true;
}

void ELFFileInfo::unloadSegments()
{

  SEGMENT_INFO *seg = m_lstSegs.next;
  while (seg != &m_lstSegs) {
    m_ElfMgr->delSegmentEntry(seg);
    removeSegment(seg);
  }
}

/****************************************************************************/
/* VLOOM ELF manager                                                        */
/****************************************************************************/
// using FILE_ENTRY = ElfModuleMgr::FILE_ENTRY;
// using SEGMENT_ENTRY = ElfModuleMgr::SEGMENT_ENTRY;

// ElfModuleMgr::FILES ElfModuleMgr::Files = {NULL};

ElfModuleMgr::ElfModuleMgr()
{
  VLOOM_LOG(VLL_TRACE, "Initialize VLOOM's ELF file management system");
  // mMM = MemMgr::PickInstance();
  // mSegments = {NULL};
}
ElfModuleMgr::~ElfModuleMgr()
{
  /* delFile break the internal structure of Files, so we use an external loop
   */
  while (true) {
    if (getFileNum() <= 0)
      break;

    FILE_ENTRY *x = NULL;
    RB_FOREACH(x, FILES, &Files)
    {
      dlcloseExt(&x->fi);
      break;
    }
  }

  // mMM->DropInstance();
  VLOOM_LOG(VLL_TRACE, "Finalize VLOOM's ELF file management system");
}

/* can be used by external code */
FILE_INFO *ElfModuleMgr::lookupFile(const char *file_name)
{
  uint32_t handler = utils_hashstrs(file_name);
  FILE_ENTRY *entry = lookupFile(handler);
  if (entry)
    return &entry->fi;
  else
    return nullptr;
}

/* remove a file from the manager */
void ElfModuleMgr::removeFile(long file_handler)
{
  FILE_ENTRY *entry;
  FILE_ENTRY key;

  key.fi.handler = file_handler;
  entry = FILES_RB_FIND(&Files, &key);

  if (entry != NULL) {
    FILES_RB_REMOVE(&Files, entry);
    delete entry->fi.file;
    free(entry);
  }
}

/* can be used by external code */
void ElfModuleMgr::removeFile(const char *file_name)
{
  // map name to a handler
  FILE_INFO *fi = lookupFile(file_name);
  if (fi)
    removeFile(fi);
}

int ElfModuleMgr::getFileNum(void)
{
  FILE_ENTRY *x;
  int count = 0;
  RB_FOREACH(x, FILES, &Files)
  count++;

  return count;
}

/* Return true if file is opened successfully. */
FILE_INFO *ElfModuleMgr::dlopenExt(const char *file_name, ptrdiff_t offset, SymbolFilter *sf, ReloctFilter *rf)
{
  if (file_name == NULL || file_name[0] == '\0')
    return NULL;

  /* used for debugging */
  uint32_t handler = utils_hashstrs(file_name);
  m_mapHandler2Name[handler] = strdup(file_name);

  FILE_INFO *fi = lookupFile(file_name);
  if (fi)
    return fi;

  // open new file
  ELFFileInfo *info = new ELFFileInfo(this, file_name, offset);
  FILE_ENTRY *ent = addFile(info, handler);
  ent->fi.setStatus(FILE_INFO::ELFS_OPENED);

  bool res = info->collectSymbolReloct(sf, rf);
  if (res) // successfully extrace file info
    ent->fi.setStatus(FILE_INFO::ELFS_HASINFO);
  else
    ent->fi.setStatus(FILE_INFO::ELFS_NOINFO);

  return &ent->fi;
}

MAPSYMB *ElfModuleMgr::getElfSymbols(FILE_INFO *fi)
{
  if (fi)
    return fi->file->getElfSymbols();
  else
    return nullptr;
}

MAPSYMB *ElfModuleMgr::getElfSymbols(const char *file_name)
{
  FILE_INFO *fi = lookupFile(file_name);
  return getElfSymbols(fi);
}

MAPRELA *ElfModuleMgr::getElfRelocts(FILE_INFO *fi)
{
  if (fi)
    return fi->file->getElfRelocts();
  else
    return NULL;
}

MAPRELA *ElfModuleMgr::getElfRelocts(const char *file_name)
{
  FILE_INFO *fi = lookupFile(file_name);
  return getElfRelocts(fi);
}

bool ElfModuleMgr::loadElfSegments(FILE_INFO *info)
{
  if (info && !info->file)
    return info->file->loadSegments();
  else
    return false;
}

void ElfModuleMgr::unloadElfSegments(FILE_INFO *info)
{
  if (info && !info->file)
    info->file->unloadSegments();
}

SEGMENT_INFO *ElfModuleMgr::lookupSegment(const void *askfor)
{
  SEGMENT_ENTRY *entry = lookupSegmentEntry(askfor);

  const uint8_t *addr = (const uint8_t *)askfor;
  SEGMENT_INFO &seg = *(entry->seg);
  if (addr < seg.base || addr >= seg.base + seg.size)
    return NULL;
  else
    return entry->seg;
}

ElfModuleMgr::SEGMENT_ENTRY *ElfModuleMgr::lookupSegmentEntry(const void *askfor)
{
  SEGMENT_ENTRY key, *entry;
  key.base = (long)askfor;
  key.end = (long)askfor;

  entry = SEGMENTS_RB_FIND(&mSegments, &key);
  if (entry == NULL)
    return NULL;
  else
    return entry;
}

ElfModuleMgr::SEGMENT_ENTRY *ElfModuleMgr::addSegmentEntry(SEGMENT_INFO *seg)
{
  SEGMENT_ENTRY *ent = lookupSegmentEntry(seg->base);
  if (ent == NULL) {
    /* create new entry */
    ent = (SEGMENT_ENTRY *)malloc(sizeof(SEGMENT_ENTRY));
    SEGMENTS_RB_INSERT(&mSegments, ent);
    ent->base = (long)seg->base;
    ent->end = (long)seg->base + seg->size;
    ent->seg = seg;
  }

  return ent;
}

void ElfModuleMgr::delSegmentEntry(SEGMENT_INFO *seg)
{
  SEGMENT_ENTRY *ent = lookupSegmentEntry(seg->base);
  if (ent == NULL)
    return;

#define ERR_DELSEG "delete segment %p from ELF file %s"
  VLOOM_LOG(VLL_TRACE, ERR_DELSEG, ent->seg->base, ent->seg->file->m_FileName);

  /* Todo: fixing ELFFileInfo->segs chain */
  SEGMENTS_RB_REMOVE(&mSegments, ent);
  free(ent);
}

int ElfModuleMgr::getSegmentNum(void)
{
  SEGMENT_ENTRY *x;
  int count = 0;
  RB_FOREACH(x, SEGMENTS, &mSegments)
  count++;

  return count;
}