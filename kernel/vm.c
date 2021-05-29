#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "fs.h"
#include "spinlock.h"
#include "proc.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

int count_pages(struct proc*);
void page_in(uint64, pte_t *);
void page_out(struct proc*, int);

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x400000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // map kernel stacks
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}

// Initialize the one kernel_pagetable
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch h/w page table register to the kernel's page table,
// and enable paging.
void
kvminithart()
{
  w_satp(MAKE_SATP(kernel_pagetable));
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA){
    // #ifdef NONE
    // return 0;
    // #endif
    panic("walk");
  }

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) { //
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA){
    return 0;
  }

  pte = walk(pagetable, va, 0);
  if(pte == 0){
    return 0;
  }
  if((*pte & PTE_V) == 0){
    return 0;
  }
  if((*pte & PTE_U) == 0){
    return 0;
  }
  pa = PTE2PA(*pte);
  return pa;

}

// add a mapping to the kernel page" table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned. Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  a = PGROUNDDOWN(va);
  last = PGROUNDDOWN(va + size - 1);
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

void update_metadata(uint64 a){
  // Task1 - update meta_data
  // No need to update if selection = NONE
  #ifndef NONE
    struct proc* p = myproc();
    int page_idx = a/PGSIZE;
    p->meta_data[page_idx].offset = -1;
    p->meta_data[page_idx].location = NOTALLOCATED;
    #ifdef NFUA
    p->meta_data[page_idx].counter = 0;
    #endif
    #ifdef LAPA
    p->meta_data[page_idx].counter = 0xFFFFFFFF;
    #endif
    #ifdef SCFIFO
    p->meta_data[page_idx].scfifo_q = -1;
    #endif
  #endif
  
}

// Remove npages of mappings starting from va. va must be
// page-aligned. The mappings must exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0){
      // it's possible the space wasn't allocaed yet, continue to next page
      continue;
    }
    if (*pte & PTE_V){
      if(PTE_FLAGS(*pte) == PTE_V)
        panic("uvmunmap: not a leaf");

      if(do_free){
        uint64 pa = PTE2PA(*pte);
        kfree((void*)pa);
        if (myproc()->pagetable == pagetable)
          update_metadata(a);
      }
    }
    else{
      if (myproc()->pagetable == pagetable)
        update_metadata(a);
    }
    *pte = 0;
  }
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Load the user initcode into address 0 of pagetable,
// for the very first process.
// sz must be less than a page.
void
uvminit(pagetable_t pagetable, uchar *src, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pagetable, 0, PGSIZE, (uint64)mem, PTE_W|PTE_R|PTE_X|PTE_U);
  memmove(mem, src, sz);
}

int find_free_offset(struct proc* p){
  for(int i = 0; i < 16; i++){
    if (p->free_offsets[i])
      return i*PGSIZE;
  }
  panic("swapfile is full");
  return -1; // not reached
}

// Allocate PTEs and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
#ifndef NONE
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  char *mem;
  uint64 a;
  struct proc *p = myproc();

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    int page_idx = a/PGSIZE;
    // reached max pages - cannot alloc
    if(page_idx >= MAX_TOTAL_PAGES)
      return 0;
    // if p already has 16 pages in physical memory, map pagetable to swapfile
    if(count_pages(p) == MAX_PSYC_PAGES){
      page_out(p, find_free_offset(p));
    }
    // has free spots, map pageteable into physical memory
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_W|PTE_X|PTE_R|PTE_U) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    p->meta_data[page_idx].offset = -1;
    p->meta_data[page_idx].location = MEMORY;
    
    #ifdef SCFIFO
      p->meta_data[page_idx].scfifo_q = p->scfifo_max+1;
      p->scfifo_max++;
    #endif
  }  
  return newsz;
}
#endif

#ifdef NONE
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_W|PTE_X|PTE_R|PTE_U) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}
#endif

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    
    // it's possible the space wasn't allocaed yet, continue to next page
    // if(((pte = walk(old, i, 0)) == 0) || ((*pte & PTE_V) == 0) )
    if( (pte = walk(old, i, 0)) == 0)
      continue;

    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);

    if((*pte & PTE_V) != 0 ){
      if((mem = kalloc()) == 0)
        goto err;
      memmove(mem, (char*)pa, PGSIZE);
      if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
        kfree(mem);
        goto err;
      }
    }
    else if((*pte & PTE_PG) != 0){
      pte_t *new_pte;
      if ((new_pte =  walk(new, i, flags)) == 0)
        goto err;
      *new_pte |= flags;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}

uint count_one_bits(int n){
  uint count = 0;
  while (n > 0) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

int nfua_algo(struct proc* p){
  int min_idx = 0;
  uint min_counter = __UINT32_MAX__;
  for(int i = 3; i < MAX_TOTAL_PAGES; i++){
    if(p->meta_data[i].location == MEMORY && (uint)p->meta_data[i].counter < min_counter){
      min_counter = p->meta_data[i].counter;
      min_idx = i;
    }
  }
  return min_idx;
}

int lapa_algo(struct proc* p){
  int min_idx = 0;
  uint min_bits = __UINT32_MAX__;
  for(int i = 3; i < MAX_TOTAL_PAGES; i++){
    if(p->meta_data[i].location == MEMORY){
      uint bits = count_one_bits(p->meta_data[i].counter);
      if ((bits < min_bits) ||
          (bits == min_bits && p->meta_data[i].counter < p->meta_data[min_idx].counter)){
        min_bits = bits;
        min_idx = i;
      }
    }
  }
  return min_idx;
}

int scfifo_algo(struct proc* p){
  for(;;){
    int min_idx = 0;
    int min_q = __INT32_MAX__;
    for(int i = 3; i < MAX_TOTAL_PAGES; i++){
      if(p->meta_data[i].location == MEMORY){
        if(p->meta_data[i].scfifo_q < min_q){
          min_idx = i;
          min_q = p->meta_data[i].scfifo_q;
        }                     
      }
    }
    pte_t * pte = walk(p->pagetable, min_idx*PGSIZE ,0);
    // found the first pte in queue and it has not been accessed 
    if (!(*pte & PTE_A)) 
      return min_idx;

    // found the first pte in queue but it has been accessed
    // turn of pte_a flag and move the page the end of the queue
    *pte = *pte & ~PTE_A;
    p->meta_data[min_idx].scfifo_q = p->scfifo_max;
    p->scfifo_max++;
  }
  return 0; //not reached  
}

int paging_algorithm(struct proc* p){
  #ifdef NFUA
  return nfua_algo(p);
  #endif

  #ifdef LAPA
  return lapa_algo(p);
  #endif
  
  #ifdef SCFIFO
  return scfifo_algo(p);
  #endif

  return 0; //not reached
}

int count_pages(struct proc* p){
  int counter = 0;
  for(int i = 0; i < MAX_TOTAL_PAGES; i++){
    if (p->meta_data[i].location == MEMORY)
      counter++;
  }
  return counter; 
}

// finds a page to remove and write it in swapfile in the given offset
void page_out(struct proc* p, int offset){
  int idx = paging_algorithm(p);       // find page to swap out bt paging algorithm
  printf("process %d, paging out %d\n", p->pid, idx );
  uint64 va = idx*PGSIZE;
  pte_t *pte =  walk(p->pagetable, va, 0); // returns the pte found at va

  if (pte == 0){
    panic("pageout");
  }
  if (*pte == 0){ //no need to copy
    p->meta_data[idx].offset = offset;
    p->meta_data[idx].location = SWAP;
    *pte = *pte & PTE_PG;
    return;
  }

  // get the physical address of pte and write its content to swapfile
  uint64 pa = walkaddr(p->pagetable, va);
  // uint64 pa = PTE2PA(*pte);
  if(writeToSwapFile(p,(char*)pa,offset,PGSIZE) ==  -1)
    panic("write to swap");

  p->free_offsets[offset/PGSIZE] = 0;

  // free the physical memory of the page
  kfree((void*)pa);

  // turn pte_v off and turn pte_pg on
  *pte = (*pte & (~PTE_V)) | PTE_PG;

  p->meta_data[idx].offset = offset;
  p->meta_data[idx].location = SWAP;
}

// finds the page located at addr in the swapfile and read it into memory
void page_in(uint64 addr, pte_t * pte){
  struct proc* p = myproc();
  // round addres and get page index
  int page_idx = PGROUNDDOWN(addr)/PGSIZE;
  printf("process %d, paging in %d\n", p->pid, page_idx );


  if (p->meta_data[page_idx].location != SWAP)
    panic("page not in swapfile");
  

  // this offset will be cleaned, we can send it to page out if needed
  int offset = p->meta_data[page_idx].offset;
  p->free_offsets[offset/PGSIZE] = 0;
  
  char *buf, *mem;

  
  if(((buf = kalloc()) == 0) || ((mem = kalloc()) == 0))
    panic("page in: out of memory");
  
  mappages(p->pagetable, PGROUNDDOWN(addr), PGSIZE, (uint64)mem, 
    PTE_W | PTE_R | PTE_X | PTE_U);
  
  if (readFromSwapFile(p, buf ,offset, PGSIZE) == -1)
    panic("read swapfile");

  p->free_offsets[offset/PGSIZE] = 0;

  // if there are 16 pages in physical memory, move one page into swap file
  if(count_pages(p) == MAX_PSYC_PAGES){
    page_out(p, offset);
    *pte = PA2PTE((uint64)buf) | ((PTE_FLAGS(*pte)& ~PTE_PG) | PTE_V);
  }  
  else{
    *pte = PA2PTE((uint64)buf) | PTE_V;
  }
    
  sfence_vma(); //refresh TLB

  //update meta_data
  p->meta_data[page_idx].offset = -1;
  p->meta_data[page_idx].location = MEMORY;

}

void determine_pagefault(){
  struct proc *p = myproc();
  uint64 addr = r_stval();  // find the faulting address
  
  #ifndef NONE
  pte_t * pte = walk(p->pagetable, PGROUNDDOWN(addr), 0);
  // paged out
  if(addr <= p->sz && pte != 0 && *pte != 0 && (*pte & PTE_PG) &&  (*pte & ~PTE_V))
    page_in(addr, pte);

  else if (addr <= p->sz){
    printf("process %d allocating page %d, *lazy*\n", p->pid,PGROUNDDOWN(addr)/PGSIZE );
    if (uvmalloc(myproc()->pagetable,PGROUNDDOWN(addr), PGROUNDDOWN(addr) + PGSIZE) == 0)
      panic("could not allocate page");
  }
  #endif
  
  #ifdef NONE
  // valid page not yet allocated
  if (addr <= p->sz){
    if (uvmalloc(myproc()->pagetable,PGROUNDDOWN(addr), PGROUNDDOWN(addr) + PGSIZE) == 0)
      panic("could not allocate page");
  }
  #endif

  // segmentation fault
  else{
    printf("segmentaion fault: pid = %d, stval=%p\n", p->pid, addr);
    p->killed = 1;
  }
}

void update_counter(){
  struct proc* p = myproc();
  for (int i = 0 ; i < MAX_TOTAL_PAGES; i++){
    if (p->meta_data[i].location == MEMORY){
      pte_t * pte = walk(p->pagetable, i*PGSIZE ,0);
      p->meta_data[i].counter = (p->meta_data[i].counter) >> 1;
      if (*pte & PTE_A){                           // check if the page was referanced
        p->meta_data[i].counter = (p->meta_data[i].counter) | (1L << 31);    // add 1 to MSB 
        *pte = *pte & (~PTE_A);                    // turn accessed bit off
      }
    }
  }
}

void update_pages_counter(){
  #ifdef NFUA
    update_counter();
  #endif 
  #ifdef LAPA
    update_counter();
  #endif
  return;
}