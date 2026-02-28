#!/bin/bash

sudo gdb -q \
	-ex "file vmlinux" \
    -ex "set arch i386:x86-64:intel" \
    -ex "target remote localhost:1234" \
