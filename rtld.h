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


/**
 * Linked list of dependencies to shared libraries.
 **/
typedef struct rtld_lib {
  char*            filename;
  intptr_t         handle;
  struct rtld_lib* next;
} rtld_lib_t;


/**
 * Open a shared object.
 **/
rtld_lib_t* rtld_open(const char* basename);


/**
 * Resolve the address of a symbol in the shared object.
 **/
void* rtld_sym(rtld_lib_t* head, const char* name);


/**
 * Close a shared object.
 **/
int rtld_close(rtld_lib_t* lib);

