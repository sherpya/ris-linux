#!/usr/bin/env python

from sys import stdin, argv, exit as sys_exit


if __name__ == '__main__':

    if len(argv) != 2:
        print 'Bad args'
        sys_exit(1)

    data = stdin.read().strip()[0x2a*2:]

    if len(data) % 2:
        print 'Bad data'
        sys_exit(1)

    fd = open(argv[1], 'wb')
    for i in range(0, len(data), 2):
        fd.write(chr(eval('0x' + data[i] + data[i+1])))

    fd.close()
