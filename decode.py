#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Boot Information Negotiation Layer Packet decoder
#
# Copyright (C) 2005-2006 Gianluigi Tiesi <sherpya@netfarm.it>
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

if __name__ == '__main__':
    if len(argv) < 2:
        print 'Usage: decode.py hexdump1 [hexdump2] [..]'
        sys_exit()

    for f in argv[1:]:
        data = open(f).read()
        t = data[1:4].lower()
        data = data[8:]
        try:
            decode = getattr(__import__('binlsrv', globals(), locals(), []), 'decode_' + t)
        except:
            print 'Type', repr(t), 'not supported'
            continue

        print '\nDumping file:', f
        decode('['+ t.upper() +']', data)
