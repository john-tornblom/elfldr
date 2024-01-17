#   Copyright (C) 2024 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifndef PS5_PAYLOAD_SDK
    $(error PS5_PAYLOAD_SDK is undefined)
endif

PATH := $(PATH):$(PS5_PAYLOAD_SDK)/host

CC  := x86_64-ps5-payload-cc
LD  := x86_64-ps5-payload-ld
XXD := xxd

CFLAGS := -std=gnu11 -Wall -fno-plt
LDADD  := -lSceLibcInternal -lkernel_sys

all: bootstrap.elf elfldr.elf

libc.o: libc.c
	$(CC) -c $(CFLAGS) -fno-builtin -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

main-bootstrap.c: elfldr_elf.c

elfldr_elf.c: elfldr.elf
	$(XXD) -i $^ > $@

elfldr.elf: main.o elfldr.o rtld.o libc.o
	$(LD) -o $@ $^

bootstrap.elf: main-bootstrap.o bootstrap.o pt.o libc.o
	$(LD) -o $@ $^

test: bootstrap.elf
	nc -q0 $(PS5_HOST) $(PS5_PORT) < $^

clean:
	rm -f *.o elfldr_elf.c *.elf
