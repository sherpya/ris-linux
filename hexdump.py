#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Boot Information Negotiation Layer Packet Dumper
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
from binlsrv import hexdump

if __name__ == '__main__':
    if len(argv) < 2:
        print 'Usage: hexdump.py hexdump1 [hexdump2] [..]'
        sys_exit()

    for f in argv[1:]:
        data = open(f, 'rb').read()
        print '\nDumping file:', f
        hexdump(data)
