#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Inf Driver parser
#
# Copyright (C) 2004 Sherpya <sherpya@netfarm.it>
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

from codecs import utf_16_decode
from sys import argv
from glob import glob
from cPickle import dump

__version__ = '0.4'

### Compatibility with python 2.1
if getattr(__builtins__, 'True', None) is None:
    True=1
    False=0

class_guids = ['{4d36e972-e325-11ce-bfc1-08002be10318}']
classes = ['net']

exclude = ['layout.inf', 'drvindex.inf', 'netclass.inf']

debug = 0
dumpdev = 0

bustype = { 'USB'   :  1,
            'PCI'   :  5,
            'PCMCIA':  8,
            'ISAPNP': 14
            }

def csv2list(value):
    values = value.strip().split(',')
    for i in range(len(values)):
        values[i] = values[i].strip()
    return values

def str_lookup(dc, c_key):
    for key in dc.keys():
        if key.lower() == c_key.lower():
            if len(dc[key])>0:
                return dc[key].pop()
    return 'NoDesc'

def item_lookup(dc, c_key):
    for key in dc.keys():
        if key.lower() == c_key.lower():
            return dc[key]
    return None

def unquote(text):
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text

def inf_needed(filename, section):
    ### Check if driver is requested
    for key in section.keys():
        c_key   = key.lower()
        c_value = section[key][0].lower()
        if c_key=='classguid':
            if c_value not in class_guids:
                if debug > 1: print 'Skipping', filename, 'driver not in class guid list'
                return False
            else:
                return True
        elif c_key=='class':
            if c_value not in classes:
                if debug > 1: print 'Skipping', filename, 'driver not in class list'
                return False
            else:
                return True
    if debug > 1: print 'Skipping',filename,'none of class or class guid found'
    return False
    
def parse_line(sections, name, lineno, line):
    equal = line.find('=')
    comma = line.find(',')
    if equal + comma != -2:
        if equal == -1:
            equal = comma+1
        if comma == -1:
            comma = equal+1

    if debug > 2: print '[%d] [%s] equal = %d - comma = %d' % (lineno, name, equal, comma)

    if equal < comma:
        if type(sections[name])!=type({}):
            sections[name] = {}
        section = sections[name]
        key, value = line.split('=', 1)
        key = key.strip()

        ### SkipList
        if key == '0': return True
                
        if section.has_key(key):
            values = csv2list(value)
            ### SkipList
            if (len(values) < 2) or (value.find('VEN_') == -1) or (value.find('DEV_') == -1):
                return True
            oldkey = key
            key = key + '_dev_' + values[1]

            if debug > 0: print '[%d] [%s] Duplicate key %s, it will be renamed to %s' % (lineno, name, oldkey, key)

        if name == 'manufacturer':
            section[key] = [value.split(',', 1)[0].strip()]
            if debug > 1: print 'Manifacturer %s=%s' % (key, section[key])
            return True

        section[key] = csv2list(value)
        if debug > 1: print '[K] [%d] [%s] %s=%s' % (lineno, name, key, section[key])
        return True

    values = csv2list(line)
    if debug > 1: print '[V] [%d] [%s] Values = %s' % (lineno, name, ','.join(values))
    sections[name] = values
    return True

def fixup(name):
    ### Services
    if name.endswith('.services'):
        prefix = name.split('.services', 1)[0]
        check = prefix.split('.')
        if check[-1].startswith('nt'):
            check = check[:-1]
        check = check + ['services']
        name = '.'.join(check)
        return name

    check = name.split('.')

    while check[-1].isdigit():
        check = check[:-1]
    
    if check[-1].startswith('nt'):
        check = check[:-1]

    name = '.'.join(check)
    return name
    

def parse_inf(filename):
    lineno = 0
    name = ''
    sections = {}
    data = open(filename).read()
    
    ## Cheap Unicode to ascii
    if data[:2] == '\xff\xfe' or data[:2] == '\xfe\xff':
        data = utf_16_decode(data)[0]
        data = data.encode('ascii', 'ignore')

    ## De-inf fixer
    data = 'Copy'.join(data.split(';Cpy'))
    data = '\n'.join(data.split('\r\n'))

    for line in data.split('\n'):
        lineno = lineno + 1
        line = line.strip()
        line = line.split(';',1)[0]
        line = line.strip()
        
        if len(line)<1: continue

        if line[0] == ';': continue

        if line.startswith('[') and line.endswith(']'):
            if name == 'version' and not inf_needed(filename, sections[name]):
                return None
                
            name = line[1:-1].lower()
            name = fixup(name)
            sections[name] = {}
            section = sections[name]
        else:
            if section is None: continue
            if not parse_line(sections, name, lineno, line):
                break
    return sections

def scan_inf(filename):
    inf = parse_inf(filename)
    if debug > 0: print 'Parsing ', filename
    devices = {}
    if inf and inf.has_key('manufacturer'):
        devlist = []
        for sections in inf['manufacturer'].values():
            devlist = devlist + sections
            
        for devmap in devlist:
            devmap = unquote(devmap.lower())
            for dev in inf[devmap].keys():
                device = dev.split('%')[1]
                desc = unquote(str_lookup(inf['strings'], device))
                sec, hid = inf[devmap][dev]
                sec = sec.lower()

                hid = hid.upper()
                
                if dumpdev: print 'Desc:', desc
                if dumpdev: print 'hid:', hid

                mainsec = fixup(sec)
                serv_sec = mainsec + '.services'

                tmp = item_lookup(inf[serv_sec], 'AddService')
                service = tmp[0]
                sec_service = tmp[2]
                             
                driver = None
                if inf[mainsec].has_key('CopyFiles'):
                    sec_files = inf[mainsec]['CopyFiles'][0].lower()
                    sec_files = fixup(sec_files)
                    driver = inf[sec_files][0]
                else:
                    driver = inf[sec_service.lower()]['ServiceBinary'][0].split('\\').pop()
                                
                if dumpdev: print 'Driver', driver

                try:
                    char = eval(inf[mainsec]['Characteristics'][0])
                except:
                    char = 132
                    
                if dumpdev: print 'Characteristics', char        
                try:
                    btype = int(inf[mainsec]['BusType'][0])
                except:
                    try:
                        btype = bustype[hid.split('\\')[0]]
                    except:
                        btype = 0
                        
                if dumpdev: print 'BusType', btype
                if dumpdev: print 'Service', service
                if dumpdev: print '-'*78

                
                devices[hid] = { 'desc' : desc,
                                 'char' : str(char),
                                 'btype': str(btype),
                                 'drv'  : driver,
                                 'svc'  : service,
                                 'inf'  : filename.split('/').pop() }
    return devices


if __name__ == '__main__':
    if len(argv) != 2:
        print 'Usage %d: directory_with_infs' % argv[0]
    filelist = glob(argv[1]+'/*.inf')
    devlist = {}
    for inffile in filelist:
        if inffile.split('/').pop() not in exclude:
            devlist.update(scan_inf(inffile))
    
    print 'Compiled %d drivers' % len(devlist)

    fd = open('devlist.cache','w')
    dump(devlist, fd)
    fd.close()
