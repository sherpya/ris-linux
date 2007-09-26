#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Inf Cache dumper
#
# Copyright (C) 2006-2007 Gianluigi Tiesi <sherpya@netfarm.it>
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
from cPickle import load

__version__ = '0.1'

if __name__ == '__main__':
    if len(argv) != 2:
        print 'Usage: %s devlist.cache' % argv[0]
        sys_exit(-1)

    data = load(open(argv[1], 'rb'))
    keys = data.keys()
    keys.sort()
    for k in keys:
        if not k.startswith('PCI'): continue
        print '%s: %s' % (k, data[k]['inf'].lower())
        #print '%s: %s' % (k, data[k])
