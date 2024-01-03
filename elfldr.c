/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */


#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


/**
 * Linked list of dependencies to shared libraries.
 **/
typedef struct elfldr_needed {
  const char*           filename;
  void*                 handle;
  struct elfldr_needed* next;
} elfldr_needed_t;


/**
 * Context structure for the ELF loader.
 **/
typedef struct elfldr_ctx {
  uint8_t*   elf;
  Elf64_Sym* symtab;
  char*      strtab;

  void*  base_addr;
  size_t base_size;

  elfldr_needed_t *needed;
} elfldr_ctx_t;


/**
 * Search paths for share libraries.
 **/
static const char*
LD_LIBRARY_PATH[] = {
  "./",
  "/usr/lib/",
  "/usr/lib/x86_64-linux-gnu/"
};


/**
 * Log an error.
 **/
static void
logerr(const char* msg, int error) {
  fprintf(stderr, "[elfldr.elf] %s: %s\n", msg, strerror(error));
}


/**
 * Log a debug message.
 **/
static void
logdbg(const char* msg) {
  fprintf(stdout, "[elfldr.elf] %s\n", msg);
}


/**
 * Parse a PT_LOAD program header.
 **/
static int
pt_load(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  void* vaddr = ctx->base_addr + phdr->p_vaddr;

  if(!phdr->p_memsz || !phdr->p_filesz) {
    return 0;
  }

  memcpy(ctx->base_addr + phdr->p_vaddr,
	 ctx->elf + phdr->p_offset,
	 phdr->p_filesz);

  return 0;
}


/**
 * Parse a PT_DYNAMIC program header.
 **/
static int
pt_dynamic(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  Elf64_Dyn *dyn = (Elf64_Dyn*)(ctx->elf + phdr->p_offset);

  for(size_t i=0; dyn[i].d_tag!=DT_NULL; i++) {
    void *addr = ctx->base_addr + dyn[i].d_un.d_ptr;

    switch(dyn[i].d_tag) {
    case DT_SYMTAB:
      ctx->symtab = addr;
      break;

    case DT_STRTAB:
      ctx->strtab = addr;
      break;
    }
  }

  return 0;
}


/**
 * Parse a DT_NEEDED section.
 **/
static int
dt_needed(elfldr_ctx_t *ctx, const char* basename) {
  elfldr_needed_t *needed;
  char filename[PATH_MAX];
  void* handle = 0;

  for(int i=0; i<sizeof(LD_LIBRARY_PATH)/sizeof(LD_LIBRARY_PATH[0]); i++) {
    sprintf(filename, "%s/%s", LD_LIBRARY_PATH[i], basename);
    if((handle=dlopen(filename, RTLD_NOW))) {
      break;
    }
  }

  if(!handle) {
    return -1;
  }

  needed           = calloc(1, sizeof(elfldr_needed_t));
  needed->filename = filename;
  needed->handle   = handle;
  needed->next     = ctx->needed;

  ctx->needed = needed;

  return 0;
}


/**
* Parse a R_X86_64_RELATIVE relocatable.
**/
static int
r_relative(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  Elf64_Addr* value_addr = (ctx->base_addr + rela->r_offset);

  *value_addr = (Elf64_Addr)ctx->base_addr + rela->r_addend;

  return 0;
}


/**
* Parse a R_X86_64_JUMP_SLOT relocatable.
**/
static int
r_jmp_slot(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  Elf64_Sym* sym = ctx->symtab + ELF64_R_SYM(rela->r_info);
  Elf64_Addr* value_addr = ctx->base_addr + rela->r_offset;
  char* name = ctx->strtab + sym->st_name;

  for(elfldr_needed_t *n=ctx->needed; n!=NULL; n=n->next) {
    if((*value_addr=(Elf64_Addr)dlsym(n->handle, name))) {
      return 0;
    }
  }

  return -1;
}


int
elfldr_exec(uint8_t* elf, size_t size) {
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr* phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr* shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf};
  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;
  pid_t pid;

  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    logerr("ehdr->e_ident", ENOEXEC);
    return ENOEXEC;
  }

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.base_size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = (void*)min_vaddr;
    flags |= MAP_FIXED;
  } else {
    logerr("ehdr->e_type", ENOEXEC);
    return ENOEXEC;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=mmap(ctx.base_addr, ctx.base_size,
			 prot, flags, -1, 0)) == (void*)-1) {
    logerr("mmap", errno);
    return errno;
  }

  // Parse program headers.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
    case PT_LOAD:
      error = pt_load(&ctx, &phdr[i]);
      break;

    case PT_DYNAMIC:
      error = pt_dynamic(&ctx, &phdr[i]);
      break;
    }
  }

  // Load needed shared libraries.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_DYNAMIC) {
      continue;
    }
    for(Elf64_Dyn *dyn=(Elf64_Dyn*)(elf + phdr[i].p_offset);
	dyn->d_tag != DT_NULL && !error; dyn++) {
      if(dyn->d_tag == DT_NEEDED) {
	error = dt_needed(&ctx, ctx.strtab + dyn->d_un.d_val);
      }
    }
  }

  // Relocate positional independent symbols.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {

      switch(rela[j].r_info & 0xffffffffl) {
      case R_X86_64_RELATIVE:
	r_relative(&ctx, &rela[j]);
	break;

      case R_X86_64_JUMP_SLOT:
	r_jmp_slot(&ctx, &rela[j]);
	break;
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(mprotect(ctx.base_addr + phdr[i].p_vaddr,
		ROUND_PG(phdr[i].p_memsz),
		PFLAGS(phdr[i].p_flags))) {
      logerr("mprotect", errno);
      error = 1;
      break;
    }
  }

  // Spawn a new process if the ELF was loaded successfully.
  if(!error) {
    void (*_start)() = ctx.base_addr + ehdr->e_entry;
    if(!(pid=fork())) {
      _start();
      exit(0);
    }
  }

  if(munmap(ctx.base_addr, ctx.base_size)) {
    logerr("munmap", errno);
  }

  //TODO: free ctx members

  if(error) {
    return -1;
  }

  return pid;
}

