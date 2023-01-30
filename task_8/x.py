from pwn import *
import base64

pbkdf_key = """0xc0000cc100:   0x625aa437d62957dd      0xa441235369666a4d
0xc0000cc110:   0x90cf0e85863e6aef      0x6aa583d289cf987f"""
pbkdf_key = pbkdf_key.split('\n')

hexes = []
for l in pbkdf_key:
    hexes.extend(l.split()[1:])   # get the two giant nums

key_bytes = [p64(int(i,16)) for i in hexes]
key_bytes = b''.join(key_bytes)

key_b64 = base64.encodebytes(key_bytes)

print(key_b64.decode())
# 3Vcp1jekWmJNamZpUyNBpO9qPoaFDs+Qf5jPidKDpWo=