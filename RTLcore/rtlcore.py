from pwn import *

#context.arch = 'i386'
#context.terminal=['tmux', 'splitw', '-h']
p = process("./rtlcore")
#p = remote('ctf.j0n9hyun.xyz', 3011)
#get_flag = 0x8048f0d
#gdb.attach(p, 'b*0x04009c9')


print p.recvuntil("Passcode: ")