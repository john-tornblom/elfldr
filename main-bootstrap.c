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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <ps5/kernel.h>

#include "bootstrap.h"

#include "elfldr_elf.c"


/**
 * Get the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* procname) {
  int mib[4] = {1, 14, 8, 0};
  size_t buf_size = 0;
  pid_t pid = -1;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    perror("[bootstrap.elf] sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    perror("[bootstrap.elf] malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("[bootstrap.elf] sysctl");
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(procname, ki_tdname)) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


int
main(int argc, char** argv, char** envp) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  pid_t mypid = getpid();
  uint8_t caps[16];
  uint64_t authid;
  pid_t pid;
  int ret;

  if(kernel_get_ucred_caps(mypid, caps)) {
    puts("[bootstrap.elf] kernel_get_ucred_caps() failed");
    return -1;
  }

  if(kernel_set_ucred_caps(mypid, privcaps)) {
    puts("[bootstrap.elf] kernel_set_ucred_caps() failed");
    return -1;
  }

  if(!(authid=kernel_get_ucred_authid(mypid))) {
    puts("[bootstrap.elf] kernel_get_ucred_authid() failed");
    return -1;
  }

  if(kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
    puts("[bootstrap.elf] kernel_get_ucred_authid() failed");
    return -1;
  }

  if((pid=find_pid("SceVrTrackerDaemon")) < 0) {
    return -1;
  }

  if(kernel_set_ucred_caps(pid, privcaps)) {
    puts("[bootstrap.elf] kernel_set_ucred_caps() failed");
    return -1;
  }
  
  ret = bootstrap_exec(pid, elfldr_elf, elfldr_elf_len);

  if(kernel_set_ucred_authid(mypid, authid)) {
    puts("[bootstrap.elf] kernel_set_ucred_authid() failed");
    return -1;
  }

  if(kernel_set_ucred_caps(mypid, caps)) {
    puts("[bootstrap.elf] kernel_set_ucred_caps() failed");
    return -1;
  }

  return ret;
}
