from pwn import *

p = process("./yes_or_no")

print p.recvuntil("Show me your number~!")
p.sendline("9830400")
print p.recvuntil("That's cool. Follow me")