from pwn import *
import json
import time
from queue import Queue

start = time.time()
print("started at {:.3f}".format(start))

r = remote('chall.ctf.bamboofox.tw', 10369)#, level = 'debug')
print("done in {:.2f}s".format(time.time()-start))

r.recvline()
line = r.recvline()

prefix = line[7:23].decode()

print('starting proof of work')

start = time.time()
print("started at {:.3f}".format(start))

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
print("done in {:.2f}s".format(time.time()-start))

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
start = time.time()
print("started at {:.3f}".format(start))

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
print('sets received')
print("done in {:.2f}s".format(time.time()-start))

print('writing sets to file')
start = time.time()
print("started at {:.3f}".format(start))
f = open('orzNetworkSets.out','w')
f.write('\n'.join(map(json.dumps, son)))
f.close()
print("done in {:.2f}s".format(time.time()-start))

print('linking graph')
start = time.time()
print("started at {:.3f}".format(start))
graph = [[] for j in range(421)]

for node in son:
    data = {
        'mod': node['mod'],
        'base': node['base'],
        'apub': node['apub'],
        'bpub': node['bpub']
    }
    graph[node['acomp']].append([node['bcomp'],data])
    graph[node['bcomp']].append([node['acomp'],data])

vis = [False for j in range(421)]
vis[0] = True
vis[1] = True

next = Queue()
next.put(1)
prev = [None for j in range(421)]

while not next.empty():
    n = next.get()
    # print(graph[n][0])
    # print(graph[n][0][0])
    # print(graph[n][0][1])
    for links in graph[n]:
        link = links[0]
        data = links[1]
        if not vis[link]:
            vis[link] = True
            prev[link] = data
            next.put(link)
    break

print("done in {:.2f}s".format(time.time()-start))

print('writing links to file')
start = time.time()
print("started at {:.3f}".format(start))
f = open('orzNetworkLinks.out','w')
f.write('\n'.join(map(lambda x: ','.join(map(lambda y: str(y[0]), x)),graph)))
f.close()
print("done in {:.2f}s".format(time.time()-start))

print('writing graph to file')
start = time.time()
print("started at {:.3f}".format(start))
f = open('orzNetworkGraph.out','w')
f.write('\n'.join(map(json.dumps, prev)))
f.close()
print("done in {:.2f}s".format(time.time()-start))

"""
Secure connection established between computer #195 (Alice) and computer #246 (Bob).
> Diffie-Hellman modulus is 3930321783910135259, base is 559410311035390375, Alice's public key is 2493194453409635249, Bob's public key is 1310992010791251904
"""