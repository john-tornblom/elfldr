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

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "elfldr.h"


static void*
main_thread(void* args) {
  while(1) {
    elfldr_serve(9023);
  }
  return 0;
}


int
main(int argc, char** argv, char** envp) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  pid_t pid = getpid();
  uint8_t caps[16];
  pthread_t trd;

  if(kernel_get_ucred_caps(pid, caps)) {
    puts("[elfldr.elf] kernel_get_ucred_caps() failed");
    return -1;
  }

  if(kernel_set_ucred_caps(pid, privcaps)) {
    puts("[elfldr.elf] kernel_set_ucred_caps() failed");
    return -1;
  }
  return elfldr_serve(9023);
  return pthread_create(&trd, 0, main_thread, 0);
}

