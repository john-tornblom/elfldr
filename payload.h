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

#pragma once

typedef struct payload_args {
  int (*sceKernelDlsym)(int, const char*, void*);

  int rwpipe[2];
  int rwpair[2];

  unsigned long kpipe_addr;
  unsigned long kdata_base_addr;

  int payloadout[1];
} payload_args_t;
