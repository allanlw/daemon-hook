#!/usr/bin/env python

import sys

f = sys.stdin
while True:
  chunk = f.read(63)
  if not chunk: break
  ctrl = "\x00"
  if (chunk[-1] == ctrl):
    ctrl = "\x80"
  sys.stdout.write(chunk + ctrl)
