#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Windows OSLoader Modification Tool
#
# Copyright (C) 2006 Gianluigi Tiesi <sherpya@netfarm.it>
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
from string import digits, letters
from getopt import getopt
from struct import pack, unpack
import re

__version__ = '0.1'

__usage__ = """%s: [-l loader] [-p port] [-v] [-r response] inputfile
input file can be:
startrom - change OsLoader [-l] : exactly 5 chars - only if not yet changed
OsLoader - change port [-p] : 16 bit integer
         - display current port [-v] - no modification are written
           change response file [-r] : exactly 9 chars - only if not yet changed
!!! Warning it will work in-place, the original file is modified !!!
"""
arglist = 'l:p:vr:'
ppattern = re.compile(r'\x6a\x04\x68(..)\x00\x00\xff\x35', re.DOTALL)
allowed_chars = digits + letters + '.'

def check_name(name):
    for i in range(len(name)):
        if name[i] not in allowed_chars:
            return 0
    return 1

if __name__ == '__main__':
    loader = None
    port = None
    response = None
    display = None

    try:
        optlist, args = getopt(argv[1:], arglist)
        if (len(optlist) == 0) or (len(args) != 1): raise Exception
    except:
        print __usage__ % argv[0]
        sys_exit(-1)

    for arg in optlist:
        if arg[0] == '-l':
            loader = arg[1]
            continue
        if arg[0] == '-p':
            port = arg[1]
            continue
        if arg[0] == '-v':
            display = 1
            continue
        if arg[0] == '-r':
            response = arg[1]
            continue

    filename = args[0]
    data = open(filename, 'rb').read()
    if len(data) < 1024: # enough ? :P
        print 'Short read, file too small'
        sys_exit(-1)

    filetype = data[:2]

    if filetype != 'MZ':
        ### Assume pxe rom
        if loader is None or port is not None or response is not None or display is not None:
            print 'Invalid operation for startrom file'
            sys_exit(-1)
        if len(loader) != 5:
            print 'The loader should be EXACTLY 5 character'
            sys_exit(-1)
        if not check_name(loader):
            print 'Invalid character in loader name, allowed chars are:'
            print allowed_chars
        pat = re.compile(r'NTLDR', re.IGNORECASE)
        out = pat.sub(loader, data)
        if out == data:
            print 'No string was replaced, make sure that the string is not yet changed'
            sys_exit(-1)
        open(filename, 'wb').write(out)
        print 'Loader succesfully changed to', loader
        sys_exit(0)
    else:
        ### Assume OsLoader
        if loader is not None:
            print 'Invalid operation for OsLoader file'
            sys_exit(-1)

        if display is not None and (port is not None or response is not None):
            print 'Display option should be used alone'
            sys_exit(-1)

        ### Changing port
        if port is not None:
            try:
                port = int(port)
                if (port <= 0) or (port >= 0xfff):
                    raise Exception
            except:
                print 'Invalid port specified, it must be in range 1-65534'
                sys_exit(-1)
            ##
            res = ppattern.search(data)
            if res is None:
                print 'Port pattern not found in file, if you think it\'s an error, please report'
                sys_exit(-1)
            hdr = data[:res.start() + 3]
            footer = data[res.end() - 4:]
            out = hdr + pack('!H', port) + footer
            data = out

        ### Changing response file
        if response is not None:
            if len(response) != 9:
                print 'The response should be EXACTLY 9 character'
                sys_exit(-1)
            if not check_name(response):
                print 'Invalid character in response name, allowed chars are:'
                print allowed_chars
            pat = re.compile(r'winnt\.sif', re.IGNORECASE)
            out = pat.sub(response, data)
            if out == data:
                print 'No string was replaced, make sure that the string is not yet changed'
                sys_exit(-1)
            print 'Response changed to', response

        if display is None:
            open(filename, 'wb').write(out)
            print 'File succesfully modified'
        else:
            res = ppattern.search(data)
            if res is None:
                print 'Port location not found, bad file?'
                sys_exit(-1)
            port = unpack('!H', res.group(0)[3:5])[0]
            print 'OsLoader is currently using port', port

        sys_exit(0)
