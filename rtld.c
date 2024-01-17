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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtld.h"
#include "payload.h"


static int (*sceKernelLoadStartModule)(const char*, unsigned long, const void*,
				       unsigned int, void*, int*) = 0;

static int (*sceKernelStopUnloadModule)(int, unsigned long, const void*, unsigned int,
					const void*, void*) = 0;

static int (*sceKernelDlsym)(int, const char*, void*) = 0;

static const char* (*sceKernelGetFsSandboxRandomWord)(void) = 0;


static const char*
LD_LIBRARY_PATH[] = {
  "priv_ex/lib",
  "common_ex/lib",
  "priv/lib",
  "common/lib"
};


rtld_lib_t*
rtld_open(const char* basename) {
  const char *sandbox_path = sceKernelGetFsSandboxRandomWord();
  char filename[PATH_MAX];
  rtld_lib_t *lib = 0;
  int handle = -1;

  if(!strcmp(basename, "libkernel.so") ||
     !strcmp(basename, "libkernel_web.so") ||
     !strcmp(basename, "libkernel_sys.so")) {
    lib           = malloc(sizeof(rtld_lib_t));
    lib->filename = strdup(basename);
    lib->handle   = 0x2001;
    lib->next     = 0;
    return lib;
  }

  if(!sandbox_path) {
    return 0;
  }

  for(int i=0; i<sizeof(LD_LIBRARY_PATH)/sizeof(LD_LIBRARY_PATH[0]); i++) {
    sprintf(filename, "/%s/%s/%s", sandbox_path, LD_LIBRARY_PATH[i], basename);
    filename[strlen(filename)-2] = 0;
    strcat(filename, "sprx");

    if(access(filename, F_OK) < 0) {
      continue;
    }

    if((handle=sceKernelLoadStartModule(filename, 0, 0, 0, 0, 0)) > 0) {
      break;
    }
  }

  if(handle < 0) {
    return 0;
  }

  lib           = malloc(sizeof(rtld_lib_t));
  lib->filename = strdup(filename);
  lib->handle   = handle;
  lib->next     = 0;

  return lib;
}


void*
rtld_sym(rtld_lib_t* lib, const char* name) {
  void *addr = 0;

  sceKernelDlsym((int)lib->handle, name, &addr);

  return addr;
}


int
rtld_close(rtld_lib_t* lib) {
  int ret = sceKernelStopUnloadModule((int)lib->handle, 0, 0, 0, 0, 0);

  free(lib->filename);
  free(lib);

  return ret;
}


__attribute__((constructor(101))) static void
rtld_constructor(const payload_args_t *args) {
  sceKernelDlsym = args->sceKernelDlsym;
  sceKernelDlsym(0x2001, "sceKernelLoadStartModule", &sceKernelLoadStartModule);
  sceKernelDlsym(0x2001, "sceKernelStopUnloadModule", &sceKernelStopUnloadModule);
  sceKernelDlsym(0x2001, "sceKernelGetFsSandboxRandomWord", &sceKernelGetFsSandboxRandomWord);
}

