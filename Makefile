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


LOADER  := elfldr.elf
PAYLOAD := payload.elf

CC := clang
LD := ld.lld

CFLAGS := -Wall

all: $(LOADER) $(PAYLOAD)

$(LOADER): main.c elfldr.c
	$(CC) -o $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) -ffreestanding -fno-builtin -nostdlib -fPIC -o $@ $<

$(PAYLOAD): payload.o libtest.so
	$(LD) -pie -ltest -lc -L./ -L/usr/lib/x86_64-linux-gnu/ -T elf_x86_64.x -o $@ $^

libtest.so: libtest.c
	$(CC) $(CFLAGS) -ffreestanding -fno-builtin -nostdlib -fPIC -fpie -shared -o $@ $^

test: $(LOADER) $(PAYLOAD)
	./$(LOADER) ./$(PAYLOAD)

clean:
	rm -f *.o *.elf *.so
