#!/bin/bash

# This script tests the bmap-writer tool

# Create a file with random data
dd if=/dev/urandom of=test.img bs=1M count=10
dd if=/dev/urandom of=test.img bs=1M count=2 seek=12 conv=notrunc
dd if=/dev/urandom of=test.img bs=1M count=5 seek=16 conv=notrunc

# Compress the file with xz and gzip
xz   -z test.img -c   > test.img.xz
gzip -9 test.img -c   > test.img.gz

# Create a bmap file
bmaptool create test.img -o test.img.bmap

# Write the file with bmaptool as reference
bmaptool copy test.img test.img.out

# Write the file with bmap-writer
./bmap-writer test.img test.img.bmap test.w.img.out
cmp test.img.out test.w.img.out

# Write the file with bmap-writer and xz
./bmap-writer test.img.xz test.img.bmap test.w.img.out
cmp test.img.out test.w.img.out

# Write the file with bmap-writer and gzip
./bmap-writer test.img.gz test.img.bmap test.w.img.out
cmp test.img.out test.w.img.out
