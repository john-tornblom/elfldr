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
#include <stdlib.h>

#include "elfldr.h"


int
main(int argc, char** argv, char** envp) {
  FILE* file;
  long len;

  if(!(file=fopen(argv[1], "rb"))) {
    perror("fopen");
    return 1;
  }

  if(fseek(file, 0, SEEK_END)) {
    perror("fseek");
    return 1;
  }

  if((len=ftell(file)) < 0) {
    perror("ftell");
    return 1;
  }

  if(fseek(file, 0, SEEK_SET)) {
    perror("fseek");
    return 1;
  }

  unsigned char buf[len];
  if(fread(buf, 1, len, file) != len) {
    perror("fread");
    return 1;
  }

  if(fclose(file)) {
    perror("fclose");
    return 1;
  }

  if(elfldr_exec(buf, len) < 0) {
    return 1;
  }

  return 0;
}

