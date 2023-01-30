from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def new_decryptor():
    iv = get_random_bytes(16)
    key = '3Vcp1jekWmJNamZpUyNBpO9qPoaFDs+Qf5jPidKDpWo='
    key = base64.b64decode(key)

    ctxt = 'tVYup8h+bME8dMUWMkLJpkOsTbKtmGkSNECUcUyNz7wILWuG2GjxVmn0SuzOptDwhbxNjEe+Us0kabAIFYBy+Q=='
    ctxt = base64.b64decode(ctxt)
    cipher = AES.new(key, AES.MODE_CBC, ctxt[:AES.block_size])
    return cipher

def decrypt(cipher, ctxt):
    if not cipher:
        ctxt = 'OtN0gelXN4Pdd4npAzSlq+tfTzerNmS+hOo++P4rMvWe8B2bzmdMgoNbABO0q02CXyt4OTWCZ8xjkfMXb8WpDQ=='
    ctxt = base64.b64decode(ctxt)
    cipher = new_decryptor()
    r = cipher.decrypt(ctxt)
    return r

if __name__ == "__main__":
    r = decrypt(new_decryptor(), 'OtN0gelXN4Pdd4npAzSlq+tfTzerNmS+hOo++P4rMvWe8B2bzmdMgoNbABO0q02CXyt4OTWCZ8xjkfMXb8WpDQ==')
    print(r) # b"eR/+3\t\x8c'\x89N\xb3\xc8\xe0\x0cr\xb421c2893f-61e0-11ed-96ee-9cb6d0b8\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"