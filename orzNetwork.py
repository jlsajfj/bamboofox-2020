from pwn import *


r = remote('chall.ctf.bamboofox.tw', 10369, level = 'debug')

r.recvline()
line = r.recvline()

prefix = line[7:23].decode()

import hashlib
difficulty = 20
zeros = '0' * difficulty

def is_valid(digest):
    if sys.version_info.major == 2:
        digest = [ord(i) for i in digest]
    bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
    return bits[:difficulty] == zeros


i = 0
while True:
    i += 1
    s = prefix + str(i)
    if is_valid(hashlib.sha256(s.encode()).digest()):
        # print(i)
        break
r.sendline(str(i))
r.sendline()
r.recvline()

#this is actual data
print(r.recvline().decode().split(':')[1:])
print(r.recvline())

"""
Secure connection established between computer #195 (Alice) and computer #246 (Bob).
> Diffie-Hellman modulus is 3930321783910135259, base is 559410311035390375, Alice's public key is 2493194453409635249, Bob's public key is 1310992010791251904
"""