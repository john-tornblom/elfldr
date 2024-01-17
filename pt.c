/* Copyright (C) 2023 John Törnblom

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

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include <sys/wait.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>

#include "pt.h"


int
pt_attach(pid_t pid) {
  if(ptrace(PT_ATTACH, pid, 0, 0) == -1) {
    return -1;
  }

  if(waitpid(pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
pt_detach(pid_t pid) {
  if(ptrace(PT_DETACH, pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
pt_getregs(pid_t pid, struct reg *r) {
  return ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}


int
pt_setregs(pid_t pid, const struct reg *r) {
  return ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}


int
pt_getint(pid_t pid, intptr_t addr) {
  return ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
}


int
pt_setint(pid_t pid, intptr_t addr, int val) {
  return ptrace(PT_WRITE_D, pid, (caddr_t)addr, val);
}


int
pt_copyin(pid_t pid, void* buf, intptr_t addr, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = PIOD_WRITE_D,
    .piod_offs = (void*)addr,
    .piod_addr = buf,
    .piod_len = len};

  while(ptrace(PT_IO, pid, (caddr_t)&iod, 0)) {
    if(errno != EAGAIN) {
      return -1;
    }
  }

  return 0;
}


int
pt_setlong(pid_t pid, intptr_t addr, long val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


static int
pt_step(int pid) {
  if(ptrace(PT_STEP, pid, (caddr_t)1, 0)) {
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    return -1;
  }

  return 0;
}


static uint64_t
pt_call(pid_t pid, intptr_t addr, ...) {
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;

  va_start(ap, addr);
  jmp_reg.r_rdi = va_arg(ap, uint64_t);
  jmp_reg.r_rsi = va_arg(ap, uint64_t);
  jmp_reg.r_rdx = va_arg(ap, uint64_t);
  jmp_reg.r_rcx = va_arg(ap, uint64_t);
  jmp_reg.r_r8  = va_arg(ap, uint64_t);
  jmp_reg.r_r9  = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


static uint64_t
pt_syscall(pid_t pid, int sysno, ...) {
  intptr_t addr = kernel_dynlib_resolve(pid, 0x2001, "HoLVWNanBBc");
  struct reg jmp_reg;
  struct reg bak_reg;
  va_list ap;

  if(!addr) {
    return -1;
  } else {
    addr += 0xa;
  }

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;
  jmp_reg.r_rax = sysno;

  va_start(ap, sysno);
  jmp_reg.r_rdi = va_arg(ap, uint64_t);
  jmp_reg.r_rsi = va_arg(ap, uint64_t);
  jmp_reg.r_rdx = va_arg(ap, uint64_t);
  jmp_reg.r_r10 = va_arg(ap, uint64_t);
  jmp_reg.r_r8  = va_arg(ap, uint64_t);
  jmp_reg.r_r9  = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


int
pt_jitshm_create(pid_t pid, intptr_t name, size_t size, int flags) {
  return (int)pt_syscall(pid, 0x215, name, size, flags);
}


int
pt_jitshm_alias(pid_t pid, int fd, int flags) {
  return (int)pt_syscall(pid, 0x216, fd, flags);
}


intptr_t
pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags,
	int fd, off_t off) {
  return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}


int
pt_munmap(pid_t pid, intptr_t addr, size_t len) {
  return pt_syscall(pid, SYS_munmap, addr, len);
}


int
pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot) {
  return pt_syscall(pid, SYS_mprotect, addr, len, prot);
}


int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall(pid, SYS_close, fd);
}

int
pt_socket(pid_t pid, int domain, int type, int protocol) {
  return (int)pt_syscall(pid, SYS_socket, domain, type, protocol);
}


int
pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
	      socklen_t optlen) {
  return (int)pt_syscall(pid, SYS_setsockopt, fd, level, optname, optval,
			 optlen);
}


int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t faddr = kernel_dynlib_resolve(pid, 0x2001, "-Jp7F+pXxNg");
  return (int)pt_call(pid, faddr, pipefd);
}


void
pt_perror(pid_t pid, const char *s) {
  intptr_t faddr = kernel_dynlib_resolve(pid, 0x2001, "9BcDykPmo1I"); //__error
  intptr_t addr = pt_call(pid, faddr);
  int err = pt_getint(pid, addr);
  char buf[255];

  strcpy(buf, s);
  strcat(buf, ": ");
  strcat(buf, strerror(err));
  puts(buf);
}
