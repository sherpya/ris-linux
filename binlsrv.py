#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4 -*-
#
# Boot Information Negotiation Layer - OpenSource Implementation
#
# Copyright (C) 2005 Gianluigi Tiesi <sherpya@netfarm.it>
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

from socket import socket, AF_INET, SOCK_DGRAM, getfqdn
from codecs import utf_16_le_decode, utf_16_le_encode, ascii_encode
from struct import unpack, pack
from sys import argv, exit as sys_exit
from time import sleep, time
from cPickle import load
from os import chdir, getpid

__version__ = '0.5'

#############

WELCOME  ='/mnt/disk/ris/OSChooser/English/welcome.osc'
BASEPATH ='/mnt/disk/ris/OSChooser/English/'
LOGFILE  = '/var/log/binlsrv.log'

#############

NTLM_NEGOTIATE    = 1
NTLM_CHALLENGE    = 2
NTLM_AUTHENTICATE = 3
NTLM_ANY          = 0

#define NTLMSSP_NEGOTIATE_UNICODE          0x00000001
#define NTLMSSP_NEGOTIATE_OEM              0x00000002
#define NTLMSSP_REQUEST_TARGET             0x00000004
#define NTLMSSP_NEGOTIATE_SIGN             0x00000010
#define NTLMSSP_NEGOTIATE_SEAL             0x00000020
#define NTLMSSP_NEGOTIATE_LM_KEY           0x00000080
#define NTLMSSP_NEGOTIATE_NTLM             0x00000200
#define NTLMSSP_NEGOTIATE_00001000         0x00001000
#define NTLMSSP_NEGOTIATE_00002000         0x00002000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN      0x00008000
#define NTLMSSP_TARGET_TYPE_DOMAIN         0x00010000
#define NTLMSSP_TARGET_TYPE_SERVER         0x00020000
#define NTLMSSP_NEGOTIATE_NTLM2            0x00080000
#define NTLMSSP_NEGOTIATE_TARGET_INFO      0x00800000
#define NTLMSSP_NEGOTIATE_128              0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000

# NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_UNICODE
# NTLMSSP_NEGOTIATE_NTLM
#0x00000000
#      2 5

#0x00018206 ->
#         X -> NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_OEM
#       X   -> NTLMSSP_NEGOTIATE_NTLM
#      X    -> NTLMSSP_NEGOTIATE_ALWAYS_SIGN
#     X     -> NTLMSSP_TARGET_TYPE_DOMAIN

#0x00808011 ->
#         X -> NTLMSSP_NEGOTIATE_UNICODE
#        X  -> NTLMSSP_NEGOTIATE_SIGN
#      X    -> NTLMSSP_NEGOTIATE_ALWAYS_SIGN
#    X      -> NTLMSSP_NEGOTIATE_TARGET_INFO

#0xa2898215 ->
#         X -> NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET
#        X  -> NTLMSSP_NEGOTIATE_SIGN
#       X   -> NTLMSSP_NEGOTIATE_NTLM
#      X    -> NTLMSSP_NEGOTIATE_ALWAYS_SIGN
#     X     -> NTLMSSP_NEGOTIATE_NTLM2 | NTLMSSP_TARGET_TYPE_DOMAIN
#   X       -> ???
#  X        -> ???


#0xC000006FL The user is not allowed to log on at this time.
#0xC0000070L The user is not allowed to log on from this workstation.
#0xC0000071L The password of this user has expired.
#0xC0000072L Account currently disabled.
#0xC0000193L This user account has expired.
#0xC0000224L The user.s password must be changed before logging on the first time.

AUTH_FAIL = 0x8009030cL
AUTH_OK   = 0x00000000L

MAGIC = 'KGS!@#$%'
C = '\x81'
S = '\x82'

FILEREQ   = C+'RQU'
FILEREPLY = S+'RSU'

NEG       = C+'NEG'
CHL       = S+'CHL'

AUT       = C+'AUT'
RES       = S+'RES'

NCQ       = C+'NCQ'
NCR       = S+'NCR'

REQ       = C+'REQ'
RSP       = S+'RSP'

# Session expired, only works with code 0x1
UNR       = S+'UNR'

myfqdn = getfqdn()
myhostinfo = myfqdn.split('.', 1)
mydomain = myhostinfo.pop()
# workaround if hosts files is broken
try:
    myhostname = myhostinfo.pop()
except:
    myhostname = mydomain
    
server_data = {
    'domain': mydomain.upper(),
    'name'  : myhostname.upper(),
    'dnsdm' : mydomain,
    'fqdn'  : myfqdn
    }

tr_table = {
    '%SERVERNAME%'        : server_data['name'],
    '%SERVERDOMAIN%'      : server_data['domain'],
    '%MACHINENAME%'       : 'client',
    '%NTLMV2Enabled%'     : '0',
    '%ServerUTCFileTime%' : str(int(time()))
    }

devlist = None

regtype = [ 'REG_NONE', 'REG_SZ', 'REG_EXPAND_SZ', 'REG_BINARY', 'REG_DWORD', 'REG_MULTI_SZ' ] 
codes   = [ 'NULL', 'NAME', 'DOMAIN', 'FQDN', 'DNSDM', 'DNSDM2' ]

NULL = chr(0x0)

AUTH_U1   = 'N\x11\x155F\r\xa6\xeb' # Challenge
AUTH_U2   = '\x05\x02\xce\x0e\x00\x00\x00\x0f'

NTLM      = 'NTLMSSP\x00'

### Logger class wrapper (Sorin Sbarnea <sorin@intersol>)
class Log:
    """file like for writes with auto flush after each write
    to ensure that everything is logged, even during an
    unexpected exit."""
    def __init__(self, f):
        self.f = f
    def write(self, s):
        self.f.write(s)
        self.f.flush()

def utf2ascii(text):
    #return text.decode('utf-16-le', 'ignore').encode('ascii', 'ignore')
    return ascii_encode(utf_16_le_decode(text, 'ignore')[0], 'ignore')[0]

def ascii2utf(text):
    #return text.encode('utf-16-le')
    return utf_16_le_encode(text)[0]

def get_packet(s):
    data, addr = s.recvfrom(1024)
    pktype = data[:4]
    data = data[4:]
    l = unpack('<I', data[:4])[0]
    print 'Recv %s len = %d' % (pktype[1:], l)
    data = data[4:]
    return addr, pktype, data

def translate(text):
    for tr in tr_table.keys():
        text = tr_table[tr].join(text.split(tr))
    return text

def send_file(s, addr, u1, filename):
    reply = FILEREPLY
    try:
        data = open(filename).read()
    except:
        print 'Cannot find file', filename
        return

    data = translate(data)
    
    l = pack('<I', len(data) + len(u1) + 1)
    reply = reply + l + u1 + data + NULL
    print 'Sending', filename
    s.sendto(reply, addr)

def send_challenge(s, addr, sd):
    domain = ascii2utf(sd['domain'])
    name   = ascii2utf(sd['name'])
    dnsdm  = ascii2utf(sd['dnsdm'])
    fqdn   = ascii2utf(sd['fqdn'])

    ed = pack('<H', codes.index('DOMAIN')) + pack('<H', len(domain)) + domain + \
         pack('<H', codes.index('NAME'))   + pack('<H', len(name))   + name   + \
         pack('<H', codes.index('DNSDM'))  + pack('<H', len(dnsdm))  + dnsdm  + \
         pack('<H', codes.index('FQDN'))   + pack('<H', len(fqdn))   + fqdn   + \
         pack('<H', codes.index('DNSDM2')) + pack('<H', len(dnsdm))  + dnsdm  + \
         (NULL *4)
    
    off = 0x38
    #flags = 0xa2898215L
    flags = 0x00018206L
    data = NTLM + pack('<I', NTLM_CHALLENGE)
    data = data + encodehdr(domain, off)
    off = off + len(domain)
    data = data + pack('<I', flags)
    #data = data + AUTH_U1 + (NULL*8) # AUTH_U1 should be the challenge string
    #data = data + 'CHALLENG' + (NULL*8)
    data = data + 'CHALLEN1' + (NULL*8)
    data = data + encodehdr(ed, off)
    #data = data + AUTH_U2
    data = data + 'CHALLEN2'
    data = data + domain + ed

    reply = CHL + pack('<I', len(data)) + data
    decode_ntlm('[S]', data)   
    s.sendto(reply, addr)
        
def send_res(s, addr, data):
    reply = RES
    data = pack('<I', AUTH_OK)
    #data = pack('<I', AUTH_FAIL)
    l = pack('<I', len(data))
    reply = reply + l + data
    print 'Sending Reply 0x%x' % AUTH_OK
    s.sendto(reply, addr)

def dumphdr(data, pkt):
    return repr(utf2ascii(decodehdr(data, pkt)))

def decodehdr(data, pkt):
    slen, maxlen, off = unpack('<HHI', data[:8])
    value = pkt[off:off+slen]
    return value

def encodehdr(value, off):
    return pack('<HHI', len(value), len(value), off)

def decode_ntlm(p, data):
    pkt = data

    filename = p[1:-1] + '.log'
    open(filename, 'w').write(AUT + pack('<I', len(data)) + data)
    
    data = data[8:]

    print 'RawData', repr(data)

    t = unpack('<I', data[:4])[0]
    data = data[4:]

    if t == NTLM_NEGOTIATE:
        print p,'Packet type is NTLM_NEGOTIATE'
        flags = unpack('<I', data[:4])[0]
        print p,'Flags = 0x%x' % flags
        data = data[4:]
        print p,'Host', dumphdr(data, pkt)
        data = data[8:]
        print p,'Domain', dumphdr(data, pkt)   
    elif t == NTLM_CHALLENGE:
        print p,'Packet type is NTLM_CHALLENGE'
        
        print p,'Domain', dumphdr(data, pkt)
        data = data[8:]
        
        flags = unpack('<I', data[:4])[0]
        data = data[4:]
        print p,'Flags = 0x%x' % flags

        challenge = data[:8]
        print p, 'Challenge:', repr(challenge)
        data = data[8:]

        # NULL * 8
        data = data[8:]
                
        info = decodehdr(data, pkt)
        data = data[8:]

        while 1:
            if len(info) < 4:
                break
            t = unpack('<H', info[:2])[0]
            info = info[2:]
            l = unpack('<H', info[:2])[0]
            info = info[2:]
            value = utf2ascii(info[:l])
            info = info[l:]
            print p, '%s : %s' % (codes[t], repr(value))

        print p, 'u2 = %s' % repr(data[:8])
    elif t == NTLM_AUTHENTICATE:
        print p,'Packet type is NTLM_AUTHENTICATE'

        print p,'LANMAN challenge response', dumphdr(data, pkt)

        print p, 'u1 = 0x%x' % (unpack('<I', data[:4]))
        print p, 'u2 = 0x%x' % (unpack('<I', data[4:8]))                   
        
        data = data[8:]

        print p,'NT challenge response', dumphdr(data, pkt)
        #print p,'NT challenge response', repr(utf2ascii(decodehdr(data, pkt)[:52]))
        data = data[8:]

        print p,'Domain to auth', dumphdr(data, pkt)
        data = data[8:]

        print p,'Username', dumphdr(data, pkt)
        data = data[8:]

        print p,'Workstation', dumphdr(data, pkt)
        data = data[8:]

        print p,'SessionKey', dumphdr(data, pkt)
        data = data[8:]

        flags = unpack('<I', data[:4])[0]
        data = data[4:]
        print p,'Flags = 0x%x' % flags
    elif t == NTLM_ANY:
        print p,'Packet type is NTLM_ANY'

decode_aut = decode_ntlm

## Only PCI supported for now
def send_ncr(s, addr, vid, pid, subsys):
    global devlist

    #reply = open('vmware.hex').read()
    #decode_ncr('[VmWare]', reply[8:])
    #s.sendto(reply, addr)
    #return

    #vid = 0x10b7
    #pid = 0x9200
    #subsys = 0x100010B7
    
    device = 'PCI\\VEN_%04X&DEV_%04X' % (vid, pid)
    device_sub = device + '&SUBSYS_%08X' % subsys

    dev = None
    try:
        print 'Checking', device_sub
        dev = devlist[device_sub]
        dev_uni = device_sub
    except:
        try:
            print 'Checking', device
            dev = devlist[device]
            dev_uni = device
        except: pass

    if dev is None:
        reply = NCR + pack('<I', 0x4) + pack('<I', 0xc000000dL)
        print 'Driver not found'
        s.sendto(reply, addr)
        return

    print 'Found', dev_uni, 'in', dev['inf']
    
    unidata = ascii2utf(dev_uni)    + (NULL *2) + \
              ascii2utf(dev['drv']) + (NULL *2) + \
              ascii2utf(dev['svc']) + (NULL *2)

    drv_off = 0x24    + (len(dev_uni)+1)    * 2
    svc_off = drv_off + (len(dev['drv'])+1) * 2
    p_off   = svc_off + (len(dev['svc'])+1) * 2 

    parms = 'Description\x002\x00'     + dev['desc']  + '\x00' + \
            'Characteristics\x001\x00' + dev['char']  + '\x00' + \
            'BusType\x001\x00'         + dev['btype'] + '\x00\x00'

    plen = len(parms)

    # Now packet creation
    data = pack('<I', 0x0)            # Result: ok
    data = data + pack('<I', 0x2)     # Type
    data = data + pack('<I', 0x24)    # base offset
    data = data + pack('<I', drv_off) # Driver offset
    data = data + pack('<I', svc_off) # Service offset 
    data = data + pack('<I', plen)    # params len
    data = data + pack('<I', p_off)   # params offset
    
    data = data + unidata
    data = data + parms

    decode_ncr('[S]', data)
    reply = NCR + pack('<I', len(data)) + data + (NULL*2)
    s.sendto(reply, addr)

def decode_ncr(p, data):
    result = unpack('<I', data[:4])[0]

    if result != 0x0:
        if result == 0xc000000dL:
            value = 'Driver not found'
        else:
            value = 'Unknown Error'
        print p, 'NCR Failed - %s (code 0x%x)' % (value, result)
        return

    pktlen = len(data)
    pkt = data
    print p, 'Packet len = 0x%x (%d)' % (pktlen, pktlen)
    print p, 'Result code: 0x%x' % result
    data = data[4:] # 0x0 = OK

    print p,'type: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x2 - fixed (type?)
    
    b_off = unpack('<I', data[:4])[0]
    print p, 'base offset = 0x%x (%d)' % (b_off, b_off)
    data = data[4:] # 0x24 - fixed

    drv_off = unpack('<I', data[:4])[0]
    print p, 'drv_off = 0x%x (%d)' % (drv_off, drv_off)
    #print p, '---->', pkt[drv_off-8:].replace('\x00','.')
    data = data[4:] # 0x50 - offset to driver file, -8 from start of packet

    srv_off = unpack('<I', data[:4])[0]
    print p,'srv_off: 0x%x (%d) -> %d from start' % (srv_off, srv_off, srv_off-8)
    #print p,'--->', pkt[srv_off-8:]
    #print p,'--->', data[srv_off-32:]
    data = data[4:] # 0x6a - offset for unicode string to service name

    plen = unpack('<I', data[:4])[0]
    print p,'plen: 0x%x (%d)' % (plen, plen)
    data = data[4:] # 0xcc - size of params (wihout ending 2*NULL)

    p_off = unpack('<I', data[:4])[0]
    print p,'p_off: 0x%x (%d) -> %d from start' % (p_off, p_off, p_off-8)
    #print p, '--->', pkt[p_off-8:].replace('\x00', '.')
    data = data[4:] # 0x76 - offset from start for params
    
    s1 = data.find('\x00\x00')
    hid = utf2ascii(data[:s1+1])
    data = data[s1+3:]
    print p, 'hid: %s - Len 0x%x (%d)' % (hid, len(hid), len(hid))

    s1 = data.find('\x00\x00')
    drv = utf2ascii(data[:s1+1])
    data = data[s1+3:]
    print p, 'drv: %s - Len 0x%x (%d)' % (drv, len(drv), len(drv))

    s1 = data.find('\x00\x00')
    srv = utf2ascii(data[:s1+1])
    data = data[s1+3:]
    print p, 'srv: %s - Len 0x%x (%d)' % (srv, len(srv), len(srv))

    sets = data.split(NULL)
    parms = 0
    for i in range(0, len(sets), 3):
        if sets[i] == '':
            break
        if sets[i+2] == '':
            continue
        name  = sets[i]
        try:
            t = int(sets[i+1])
        except:
            t = 0
        value = sets[i+2]
        print p, '%s (%s [%d]) = %s' % (name, regtype[t], t, value)
        parms = parms + 1
    print p, 'Total Params:', parms

def send_ncq(s, vid, pid, subsys, spath):
    #vid    = 0x1022
    #pid    = 0x2000
    #rev_u1 = 0x2
    #rev_u2 = 0x0
    #rev_u3 = 0x0
    #rev    = 0x10
    #rev2   = 0x88
    #subsys = 0x20001022
    #spath  = '\\\\Attila\\RemInst\\winpe'
    #vid     = 0x10b7
    #pid     = 0x9200
    rev_u1  = 0x2
    rev_u2  = 0x0
    rev_u3  = 0x0
    rev_u4  = 0x0
    rev     = 0x0
    rev2    = 0x0
    #subsys  = 0x0
    #spath  = '\\\\Attila\RemInst\\Setup\\Italian\\IMAGES\\WINDOWS'
    
    data = pack('<I', 0x2)                # u1
    data = data + pack('<I', 0x0)         # u2
    data = data + pack('<I', 0x9a290c00L) # u3
    data = data + pack('<I', 0x1371)      # u4
    data = data + pack('<I', 0x0)         # u5
    data = data + pack('<I', 0x0)         # u6
    data = data + pack('<I', 0x2)         # u7
    data = data + pack('<H', vid)
    data = data + pack('<H', pid)
    data = data + chr(rev_u1) + chr(rev_u2) + chr(rev_u3) 
    data = data + chr(rev)
    data = data + pack('<I', rev2)
    data = data + pack('<I', subsys)
    data = data + pack('<H', len(spath)) + spath + (NULL *2)

    reply = NCQ + pack('<I', len(data)) + data
    decode_ncq('[R]', data)
    s.send(reply)

def decode_ncq(p, data):
    #print p,'u1: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x2

    #print p,'u2: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x0

    #print p,'u3: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x9a290c00

    #print p,'u4: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x1371

    #print p,'u5: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x0

    #print p,'u6: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x0

    #print p,'u7: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x2
    
    vid = unpack('<H', data[:2])[0]
    print p,'Vid: 0x%x' % vid
    data = data[2:]
    pid = unpack('<H', data[:2])[0]
    print p,'Pid: 0x%x' % pid
    data = data[2:]

    print p, 'rev_u1 = 0x%x' % unpack('<B', data[0])
    print p, 'rev_u2 = 0x%x' % unpack('<B', data[1])
    print p, 'rev_u3 = 0x%x' % unpack('<B', data[2])
    print p, 'rev    = 0x%x' % unpack('<B', data[3])
    data = data[4:]
    
    print p, 'rev2   = 0x%x' % unpack('<I', data[:4])
    data = data[4:]

    subsys = unpack('<I', data[:4])[0]
    print p, 'subsys = 0x%x' % subsys
    data = data[4:]

    l = unpack('<H', data[:2])[0]
    data = data[2:]

    data = data[:l]
    #print p,'data:', data.replace('\x00','')
    return vid, pid, subsys


def decode_req(p, data):
    print p, 'Decoding REQ:'

    print p,'f1: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x1

    print p,'f2: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x10001

    print p,'f3: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x10

    print p,'f4: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x1


    print p,'u1: 0x%x' % unpack('<I', data[:4])
    data = data[4:]

    print p,'u2: 0x%x' % unpack('<I', data[:4])
    data = data[4:]

    ### end of fixed data
    print 'Data:', repr(data)
    
def send_req(s, addr):
    reply = open('data1.req').read()
    #reply = REQ + pack('<I', len(data))
    s.sendto(reply, addr)    

def decode_rsp(p, data):
    print p, 'Decoding RSP:'
    
    print p,'u1: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x1

    print p,'u2: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x10001

    print p,'u3: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x10

    print p,'u4: 0x%x' % unpack('<I', data[:4])
    data = data[4:] # 0x1

    ### end of fixed data
    print 'Data:', repr(data)
    
def send_rsp(s, addr, data):
    data = open('data1.rsp').read()[8:]
    reply = RSP
    l = pack('<I', len(data))
    reply = reply + l + data
    print 'Sending RSP'
    decode_rsp('[S]', data)
    s.sendto(reply, addr)
    
def send_unr(s, addr):
    reply = UNR
    data = pack('<I', 0x1)
    l = pack('<I', len(data))
    reply = reply + l + data
    print 'Sending UNR (Session Expired)'
    s.sendto(reply, addr)
    
if __name__ == '__main__':
    ### Daemon Mode
    ### Unix only
    if len(argv) > 1 and (argv[1] == '--daemon' or argv[1] == '-d'):
        try:
            from os import fork
            from posix import close
        except:
            print 'Daemon mode is not supported on this platform (missing fork() syscall or posix module)'
            sys_exit(-1)

        import sys

        if (fork()): sys_exit()
        
        close(sys.stdin.fileno())
        sys.stdin  = open('/dev/null')
        
        close(sys.stdout.fileno())
        sys.stdout = Log(open(LOGFILE, 'a+'))
        
        close(sys.stderr.fileno())
        sys.stderr = Log(open(LOGFILE, 'a+'))

    try:
        devlist = load(open('devlist.cache'))
    except:
        print 'Could not load devlist.cache, build it with infparser.py'
        sys_exit(-1)
        
    print 'Succesfully loaded %d devices' % len(devlist)
    chdir('/')

    s = socket(AF_INET, SOCK_DGRAM)
    s.bind(('', 4011))
    
    print 'Binlserver started... pid %d' % getpid()
    while 1:
        addr, t, data = get_packet(s)
        if t == FILEREQ:
            u1 = data[:7*4]
            data = data[7*4:]
            if data == '\n':
                send_file(s, addr, u1, WELCOME)
            else:
                if data.lower().startswith('launch'):
                    send_file(s, addr, u1, BASEPATH+'warning.osc')
                print 'RawData:',repr(data)
                filename = data.strip().lower() + '.osc'
                print 'Client requested:', filename
                send_file(s, addr, u1, BASEPATH+filename)                
        elif t == NEG:
            decode_ntlm('[R]', data)
            print 'NEG request, sending CHALLENGE'
            send_challenge(s, addr, server_data)
            sleep(1)
        elif t == AUT:
            print 'AUT request, sending ok'
            decode_ntlm('[R]', data)
            send_res(s, addr, data)
            sleep(1)
        elif t == NCQ:
            print 'NCQ Driver request'
            #open('req.hex','w').write(data)
            vid, pid, subsys = decode_ncq('[R]', data)
            send_ncr(s, addr, vid, pid, subsys)
        elif t == REQ:
            print 'REQ request, sending RSP'
            decode_req('[R]', data)
            open('out.hex','w').write(REQ+pack('<I',len(data))+data)
            send_unr(s, addr)
            #send_rsp(s, addr, data)
        else:
            print 'Unknown Request: ', t[1:]
            print 'Data: ', repr(data)
            open('out.hex','w').write(data)
