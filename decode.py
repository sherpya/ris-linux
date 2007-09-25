#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Boot Information Negotiation Layer Packet decoder
#
# Copyright (C) 2005-2007 Gianluigi Tiesi <sherpya@netfarm.it>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
# ======================================================================

from sys import argv, exit as sys_exit
from binlsrv import C, S, MAGIC_COOKIE, hexdump

if __name__ == '__main__':
    if len(argv) < 2:
        print 'Usage: decode.py hexdump1 [hexdump2] [..]'
        sys_exit()

    for f in argv[1:]:
        data = open(f).read()

        if (data[0] == C) or (data[0] == S):
            t = data[1:4].lower()
            data = data[8:]
        elif data[0xec:0xec+4] == MAGIC_COOKIE:
            t = 'bootp'
        else:
            print 'Invalid Packet'
            hexdump(data)
            continue

        try:
            decode = getattr(__import__('binlsrv', globals(), locals(), []), 'decode_' + t)
        except:
            print 'Type', repr(t), 'not supported'
            hexdump(data)
            continue

        print '\nDumping file:', f
        decode('['+ t.upper() +']', data)
