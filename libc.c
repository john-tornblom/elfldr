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

#include "payload.h"


#define RTLD_DECL(name)				     \
  static void* __ptr_##name __attribute__((used));   \
  asm(".intel_syntax noprefix\n"		     \
      ".global " #name "\n"			     \
      ".type " #name " @function\n"		     \
      #name ":\n"				     \
      "jmp qword ptr [rip + __ptr_" #name "]\n");

RTLD_DECL(__error);
RTLD_DECL(accept);
RTLD_DECL(access);
RTLD_DECL(bind);
RTLD_DECL(close);
RTLD_DECL(dup);
RTLD_DECL(dup2);
RTLD_DECL(getpid);
RTLD_DECL(kill);
RTLD_DECL(listen);
RTLD_DECL(mmap);
RTLD_DECL(mprotect);
RTLD_DECL(munmap);
RTLD_DECL(open);
RTLD_DECL(pthread_create);
RTLD_DECL(ptrace);
RTLD_DECL(read);
RTLD_DECL(sleep);
RTLD_DECL(setsockopt);
RTLD_DECL(socket);
RTLD_DECL(sysctl);
RTLD_DECL(sysctlbyname);
RTLD_DECL(waitpid);

RTLD_DECL(free);
RTLD_DECL(malloc);
RTLD_DECL(memcmp);
RTLD_DECL(memcpy);
RTLD_DECL(memset);
RTLD_DECL(perror);
RTLD_DECL(printf);
RTLD_DECL(puts);
RTLD_DECL(realloc);
RTLD_DECL(sprintf);
RTLD_DECL(strcat);
RTLD_DECL(strcmp);
RTLD_DECL(strcpy);
RTLD_DECL(strdup);
RTLD_DECL(strerror);
RTLD_DECL(strlen);
RTLD_DECL(vsprintf);

#undef RTLD_DECL


__attribute__((constructor(101))) static void
libc_constructor(const payload_args_t *args) {
#define RTLD_SYM(id, name) args->sceKernelDlsym(id, #name, &__ptr_##name)
  RTLD_SYM(0x2001, __error);
  RTLD_SYM(0x2001, accept);
  RTLD_SYM(0x2001, access);
  RTLD_SYM(0x2001, bind);
  RTLD_SYM(0x2001, close);
  RTLD_SYM(0x2001, dup);
  RTLD_SYM(0x2001, dup2);
  RTLD_SYM(0x2001, getpid);
  RTLD_SYM(0x2001, kill);
  RTLD_SYM(0x2001, listen);
  RTLD_SYM(0x2001, mmap);
  RTLD_SYM(0x2001, mprotect);
  RTLD_SYM(0x2001, munmap);
  RTLD_SYM(0x2001, open);
  RTLD_SYM(0x2001, pthread_create);
  RTLD_SYM(0x2001, ptrace);
  RTLD_SYM(0x2001, read);
  RTLD_SYM(0x2001, sleep);
  RTLD_SYM(0x2001, setsockopt);
  RTLD_SYM(0x2001, socket);
  RTLD_SYM(0x2001, sysctl);
  RTLD_SYM(0x2001, sysctlbyname);
  RTLD_SYM(0x2001, waitpid);

  RTLD_SYM(0x2, free);
  RTLD_SYM(0x2, malloc);
  RTLD_SYM(0x2, memcmp);
  RTLD_SYM(0x2, memcpy);
  RTLD_SYM(0x2, memset);
  RTLD_SYM(0x2, perror);
  RTLD_SYM(0x2, printf);
  RTLD_SYM(0x2, puts);
  RTLD_SYM(0x2, realloc);
  RTLD_SYM(0x2, sprintf);
  RTLD_SYM(0x2, strcat);
  RTLD_SYM(0x2, strcmp);
  RTLD_SYM(0x2, strcpy);
  RTLD_SYM(0x2, strdup);
  RTLD_SYM(0x2, strerror);
  RTLD_SYM(0x2, strlen);
  RTLD_SYM(0x2, vsprintf);
#undef RTLD_SYM
}
