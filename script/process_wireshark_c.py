#!/usr/bin/env python

import sys
import re

data = sys.stdin.read()

parts = data.split(";")

CHUNK_SIZE = 64

for part in data.split(";"):
  s = part.strip()
  if not s: break
  matches = re.findall("0x[0-9A-F]{2}", s)
  chunk = "".join(chr(int(x, 0)) for x in matches)
  assert len(chunk) < CHUNK_SIZE

  ctrl_byte = "\x00"
  if chunk[-1] == ctrl_byte:
    ctrl_byte = "\x80"

  while len(chunk) < CHUNK_SIZE - 1:
    chunk += ctrl_byte


  sys.stdout.write(chunk + ctrl_byte)
