from pwn import *
import json

r = remote('chall.ctf.bamboofox.tw', 10369)#, level = 'debug')

r.recvline()
line = r.recvline()

prefix = line[7:23].decode()

print('starting proof of work')

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

print('proof of work complete')

cnt = int(r.recvline().decode().split()[6])

def comp_number(line: str) -> (int,int):
    return list(map(lambda x: int(x.split()[0]), line.split(" #")[1:]))

def shared_secret(line: str):
    s = list(map(lambda x: int(x.split()[-1]), line.split(", ")))
    # print(s)
    
    return s

def edge_to_dict():
    link = comp_number(recvstr())
    dhke = shared_secret(recvstr())
    d = {
        'acomp': link[0],
        'bcomp': link[1],
        'mod': dhke[0],
        'base': dhke[1],
        'apub': dhke[2],
        'bpub': dhke[3]
    }
    return d

def recvstr() -> str:
    return r.recvline().decode().strip()

print("{} sets\nreceiving data".format(cnt))
son = []
#this is actual data
temp1 = comp_number(recvstr().split(':')[1])
temp2 = shared_secret(recvstr())
son.append({
    'acomp': temp1[0],
    'bcomp': temp1[1],
    'mod': temp2[0],
    'base': temp2[1],
    'apub': temp2[2],
    'bpub': temp2[3]
})

for _ in range(cnt-1):
    son.append(edge_to_dict())

print('sets received\nwriting to file')

f = open('orzNetwork.out','w')
f.write('\n'.join(map(json.dumps, son)))
f.close()

"""
Secure connection established between computer #195 (Alice) and computer #246 (Bob).
> Diffie-Hellman modulus is 3930321783910135259, base is 559410311035390375, Alice's public key is 2493194453409635249, Bob's public key is 1310992010791251904
"""