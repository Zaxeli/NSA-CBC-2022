from Crypto.Cipher import AES
from get_keys import * 
import struct

# print(keys[0])
f_pdf= "important_data.pdf.enc"
PDF_HEADER = b"%PDF-"

with open(f_pdf, 'rb') as f:
    iv = f.read(AES.block_size*2)
    pdf_file = f.read()

# iv = pdf_file[:AES.block_size*2]
iv = bytes.fromhex(iv.decode())
print('Using iv from first AES.blocksize=16 bytes', iv, "of len", len(iv))


def decrypt_pdf(key: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    pdf_file_dec = cipher.decrypt(pdf_file)

    if PDF_HEADER in pdf_file_dec:
        with open('important_data.pdf','wb+') as f:
            f.write(pdf_file_dec)
        return True
#     return False


"""Decrypting a file AES: https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/#6_File_Encryption_with_AES"""
# f = open(f_pdf, 'rb')
# fsz = f.read(struct.calcsize('<Q'))
# fsz = struct.unpack('<Q', fsz)[0] # returns tuple, take first for result

# iv = f.read(AES.block_size*2)


# pdf_data = f.read(AES.block_size*5) # the encrypted data follows the filesize and IV
# f.close()

# def decrypt_pdf(key: bytes):
#     aes = AES.new(key, AES.MODE_CBC, iv)
#     ptxt = aes.decrypt(pdf_data)
#     if PDF_HEADER in ptxt:
#         with open('pdf_dec.pdf','wb+') as f:
#             f.write(ptxt)
#         return True
#     return False




