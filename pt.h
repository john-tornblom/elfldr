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

#pragma once

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>


int pt_attach(pid_t pid);
int pt_detach(pid_t pid);

int pt_getregs(pid_t pid, struct reg *r);
int pt_setregs(pid_t pid, const struct reg *r);

int pt_getint(pid_t pid, intptr_t addr);
int pt_setint(pid_t pid, intptr_t addr, int val);
int pt_setlong(pid_t pid, intptr_t addr, long val);
int pt_copyin(pid_t pid, void* buf, intptr_t addr, size_t len);

int pt_jitshm_create(pid_t pid, intptr_t name, size_t size, int flags);
int pt_jitshm_alias(pid_t pid, int fd, int flags);

intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags,
		 int fd, off_t off);
int pt_munmap(pid_t pid, intptr_t addr, size_t len);
int pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot);

int pt_socket(pid_t pid, int domain, int type, int protocol);
int pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
		  socklen_t optlen);

int pt_pipe(pid_t pid, intptr_t pipefd);
int pt_close(pid_t pid, int fd);

void pt_perror(pid_t pid, const char *s);
