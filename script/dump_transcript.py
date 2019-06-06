#!/usr/bin/env python

import sys

data = sys.stdin.read()

CHUNK_LEN = 64

num_chunks = 0

for chunk in range(0, len(data), CHUNK_LEN):
  if (chunk + CHUNK_LEN) > len(data): break
  by = data[chunk : chunk+CHUNK_LEN]

  ctrl_byte = by[-1]

  l = CHUNK_LEN-1
  while by[l-1] == ctrl_byte:
    l -= 1

  print "{0}: (len {1}) {2}".format(bin(ord(ctrl_byte)), l, repr(by[0:l]))
  num_chunks += 1

print num_chunks
