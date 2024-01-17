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

#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/user.h>

#include <ps5/kernel.h>

#include <elf.h>

#include "payload.h"
#include "rtld.h"


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


/**
 * Context structure for the ELF loader.
 **/
typedef struct elfldr_ctx {
  uint8_t*   elf;
  Elf64_Sym* symtab;
  char*      strtab;

  void*  base_addr;
  size_t base_size;

  rtld_lib_t *libseq;
} elfldr_ctx_t;


/**
 * Create shared memory.
 **/
static int
jitshm_create(char* name, size_t size, int flags) {
  return (int)syscall(0x215, name, size, flags, 0, 0, 0);
}


/**
 * Create an alias for some shared memory.
 **/
static int
jitshm_alias(int fd, int flags) {
  return (int)syscall(0x216, fd, flags, 0, 0, 0, 0);
}


/**
 * Reload a PT_LOAD program header with executable permissions.
 **/
static int
pt_reload(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  void* addr = ctx->base_addr + phdr->p_vaddr;
  size_t memsz = ROUND_PG(phdr->p_memsz);
  int prot = PFLAGS(phdr->p_flags);
  int alias_fd = -1;
  int shm_fd = -1;
  void* data = 0;
  int error = 0;

  if(!(data=malloc(memsz))) {
    perror("[elfldr.elf] malloc");
    return -1;
  }
  
  // Backup data
  memcpy(data, addr, memsz);
  
  // Create shm with executable permissions.
  if((shm_fd=jitshm_create(0, memsz, prot | PROT_WRITE)) < 0) {
    perror("[elfldr.elf] jitshm_create");
    error = -1;
  }

  // Map shm into an executable address space.
  else if((addr=mmap(addr, memsz, prot, MAP_FIXED | MAP_SHARED,
		shm_fd, 0)) == MAP_FAILED) {
    perror("[elfldr.elf] mmap");
    error = -1;
  }

  // Create an shm alias fd with write permissions.
  else if((alias_fd=jitshm_alias(shm_fd, PROT_WRITE)) < 0) {
    perror("[elfldr.elf] jitshm_alias");
    error = -1;
  }

  // Map shm alias into a writable address space.
  else if((addr=mmap(0, memsz, PROT_WRITE, MAP_SHARED,
		alias_fd, 0)) == MAP_FAILED) {
    perror("[elfldr.elf] mmap");
    error = -1;
  }

  // Resore data
  else {
    memcpy(addr, data, phdr->p_memsz);
    munmap(addr, memsz);
  }

  free(data);
  close(alias_fd);  
  close(shm_fd);

  return error;
}


/**
 * Parse a PT_LOAD program header.
 **/
static int
pt_load(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  void* addr = ctx->base_addr + phdr->p_vaddr;
  size_t memsz = ROUND_PG(phdr->p_memsz);

  if((addr=mmap(addr, memsz, PROT_WRITE | PROT_READ,
		MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		-1, 0)) == MAP_FAILED) {
    perror("[elfldr.elf] mmap");
    return -1;
  }
  memcpy(addr, ctx->elf+phdr->p_offset, phdr->p_memsz);

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

  return pt_load(ctx, phdr);
}


/**
 * Parse a DT_NEEDED section.
 **/
static int
dt_needed(elfldr_ctx_t *ctx, const char* basename) {
  rtld_lib_t* lib;

  if(!(lib=rtld_open(basename))) {
    printf("[elfldr.elf] Unable to open '%s'\n", basename);
    return -1;
  }

  lib->next = ctx->libseq;
  ctx->libseq = lib;

  return 0;
}


/**
* Parse a R_X86_64_RELATIVE relocatable.
**/
static int
r_relative(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  void* loc = ctx->base_addr + rela->r_offset;
  void* val = ctx->base_addr + rela->r_addend;

  *(intptr_t*)loc = (intptr_t)val;

  return 0;
}


/**
* Parse a R_X86_64_JUMP_SLOT relocatable.
**/
static int
r_jmp_slot(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  Elf64_Sym* sym = ctx->symtab + ELF64_R_SYM(rela->r_info);
  const char* name = ctx->strtab + sym->st_name;
  void* loc = ctx->base_addr + rela->r_offset;
  void* val = 0;

  for(rtld_lib_t *lib=ctx->libseq; lib!=0; lib=lib->next) {
    if((val=rtld_sym(lib, name))) {
      *(intptr_t*)loc = (intptr_t)val;
      return 0;
    }
  }

  printf("[elfldr.elf] Unable to resolve '%s'\n", name);

  return -1;
}


/**
* Parse a R_X86_64_GLOB_DAT relocatable.
**/
static int
r_glob_dat(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  Elf64_Sym* sym = ctx->symtab + ELF64_R_SYM(rela->r_info);
  const char* name = ctx->strtab + sym->st_name;
  void* loc = ctx->base_addr + rela->r_offset;
  void* val = 0;

  for(rtld_lib_t *lib=ctx->libseq; lib!=0; lib=lib->next) {
    if((val=rtld_sym(lib, name))) {
      *(intptr_t*)loc = (intptr_t)val;
      return 0;
    }
  }

  printf("[elfldr.elf] Unable to resolve '%s'\n", name);

  return -1;
}


/**
 * Spawn a new process and jump to the given entry point.
 **/
static pid_t
elfldr_spawn(void* entry) {
  long (*_start)(void*) = entry;
  char procname[255];
  pid_t pid = 0;

  if((pid=syscall(SYS_rfork, RFPROC | RFNOWAIT)) < 0) {
    perror("[elfldr.elf] rfork");
    return -1;
  }

  if(!pid) {
    sprintf(procname, "payload-%d.elf", getpid());
    syscall(0x1d0, -1, procname);
    syscall(SYS_setsid);
    _start(0);
    syscall(SYS_exit, 0);
  }

  return pid;
}


/**
 * Execute the given ELF in a new process.
 **/
pid_t
elfldr_exec(uint8_t* elf, size_t size) {
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr* phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr* shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf};
  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  pid_t pid = -1;
  int error = 0;
  
  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    puts("[elfldr.elf] Malformed ELF file");
    return -1;
  }

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
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
    puts("[elfldr.elf] ELF type not supported");
    return -1;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=mmap(ctx.base_addr, ctx.base_size,
			 prot, flags, -1, 0)) == MAP_FAILED) {
    perror("[elfldr.elf] mmap");
    return -1;
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

  // Apply relocations.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {

      switch(rela[j].r_info & 0xffffffffl) {
      case R_X86_64_RELATIVE:
	error = r_relative(&ctx, &rela[j]);
	break;

      case R_X86_64_JMP_SLOT:
	error = r_jmp_slot(&ctx, &rela[j]);
	break;

      case R_X86_64_GLOB_DAT:
	error = r_glob_dat(&ctx, &rela[j]);
	break;
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      error = pt_reload(&ctx, &phdr[i]);

    } else {
      if(mprotect(ctx.base_addr + phdr[i].p_vaddr,
		  ROUND_PG(phdr[i].p_memsz),
		  PFLAGS(phdr[i].p_flags))) {
	error = 1;
	perror("[elfldr.elf] mprotect");
      }
    }
  }

  if(!error) {
    pid = elfldr_spawn(ctx.base_addr + ehdr->e_entry);
  }

  while(ctx.libseq) {
    rtld_lib_t *next = ctx.libseq->next;
    rtld_close(ctx.libseq);
    ctx.libseq = next;
  }

  if(munmap(ctx.base_addr, ctx.base_size)) {
    perror("[elfldr.elf] munmap");
    error = 1;
  }

  if(error) {
    return -1;
  }

  return pid;
}


/**
 * Read an ELF from a given socket connection.
 **/
static ssize_t
elfldr_read(int connfd, uint8_t **data) {
  uint8_t buf[0x4000];
  off_t offset = 0;
  ssize_t len;

  *data = 0;
  while((len=read(connfd, buf, sizeof(buf)))) {
    *data = realloc(*data, offset + len);
    if(*data == 0) {
      perror("[elfldr.elf] realloc");
      return -1;
    }

    memcpy(*data + offset, buf, len);
    offset += len;
  }

  return offset;
}


/**
 * Accept ELF payloads from the given port.
 **/
int
elfldr_serve(uint16_t port) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  socklen_t addr_len;

  int stdout_fd;
  int stderr_fd;

  uint8_t *elf;
  size_t size;

  int connfd;
  int srvfd;

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("[elfldr.elf] socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("[elfldr.elf] setsockopt");
    close(srvfd);
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    perror("[elfldr.elf] bind");
    close(srvfd);
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    perror("[elfldr.elf] listen");
    close(srvfd);
    return -1;
  }

  stdout_fd = dup(1);
  stderr_fd = dup(2);

  while(1) {
    addr_len = sizeof(client_addr);
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      perror("[elfldr.elf] accept");
      close(connfd);
      close(srvfd);
      return -1;
    }

    // We got a connection, read ELF and launch it in the given process.
    if((size=elfldr_read(connfd, &elf))) {
      dup2(connfd, 1);
      dup2(connfd, 2);

      elfldr_exec(elf, size);
      free(elf);

      dup2(stdout_fd, 1);
      dup2(stderr_fd, 2);
    }
    close(connfd);
    break;
  }
  close(srvfd);

  return 0;
}

