"""(lambda data, key, iv: if len(data) != 0:
(lambda key, iv, data, AES: open('flag.enc', 'wb').write(AES.new(key, AES.MODE_CBC, iv).encrypt((lambda x: x + b'\x00' * (16 - len(x) % 16)(data))))(data[key:key + 16], data[iv:iv + 16], open('flag.png', 'rb').read(), __import__('Crypto.Cipher.AES').Cipher.AES) # Avoid dead code: lambda fn: __import__('os').remove(fn)('task.py'))

(__import__('requests').get('https://ctf.bamboofox.tw/rules').text.encode(), 99, 153)

(data[key:key + 16], data[iv:iv + 16], open('flag.png', 'rb').read(), __import__('Crypto.Cipher.AES').Cipher.AES)
"""
from Crypto.Cipher import AES

# honestly took longer than i'd like to admit to convert the lambda into a readable function
def enc(data):
 if len(data) != 0:
  #k = b'ewport" content='
  #i = b'">\n\t<link rel="s'
  #k, i, d = data[99:115], data[153:169], open('flag.png', 'rb').read()
  key = b'ewport" content='
  iv = b'">\n\t<link rel="s'
  f = open('flag.enc', 'wb')
  cipher = AES.new(key, AES.MODE_CBC, iv)
  encrypted = cipher.encrypt((lambda x: x + b'\x00' * (16 - len(x) %16))(open('flag.png', 'rb').read()))
  f.write(encrypted)
  f.close()
  
def enc():
 key = b'ewport" content='
 iv = b'">\n\t<link rel="s'
 cipher = AES.new(key, AES.MODE_CBC, iv)
 enc = cipher.decrypt((lambda x: x + b'\x00' * (16 - len(x) %16))(open('flag.enc', 'rb').read()))
 f = open('flag.png','wb')
 f.write(enc)
 f.close()

enc()