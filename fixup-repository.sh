#!/bin/sh
# File case fixer for pxe boot
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
REP=/mnt/disk/ris/pebldr
chown -R 0:0 $REP
find $REP -type f -exec chmod 644 {} \;
find $REP -type d -exec chmod 755 {} \;

( while read src dest;
do
   mv $REP/i386/system32/$src $REP/i386/system32/$dest
done) << EOF
kdcom.dll KDCOM.DLL
bootvid.dll BOOTVID.dll
setupreg.hiv SETUPREG.HIV
drivers/spddlang.sys drivers/SPDDLANG.SYS
drivers/wmilib.sys drivers/WMILIB.SYS
drivers/oprghdlr.sys drivers/OPRGHDLR.SYS
drivers/1394bus.sys drivers/1394BUS.SYS
drivers/pciidex.sys drivers/PCIIDEX.SYS
drivers/usbport.sys drivers/USBPORT.SYS
drivers/usbd.sys drivers/USBD.SYS
drivers/hidclass.sys drivers/HIDCLASS.SYS
drivers/hidparse.sys drivers/HIDPARSE.SYS
drivers/scsiport.sys drivers/SCSIPORT.SYS
drivers/classpnp.sys drivers/CLASSPNP.SYS
drivers/tdi.sys drivers/TDI.SYS
EOF
