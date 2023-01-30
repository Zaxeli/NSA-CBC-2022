import json
from Crypto.Cipher import AES

"""
Enumerate all possible keys
Write them to file 
but also export as var in mem

"""

def uuid_to_key(uuid):
    
    # u = uuid.split('-')
    # u = ''.join(u) + '0000'
    # k = bytes.fromhex(u)

    # # trying to use the uuid as a 256-bit (32 bytes) key
    # k = bytes(uuid, 'ascii')

    """Using the key extraction approach from `ransom.sh`"""
    # take first AES.block_size chars and convert to bytes
    u = uuid[:AES.block_size]
    k = bytes(u, 'ascii')
    return k


uuids = ["f7310de8-4df1-11eb-b008-1762ad81"] # all uuid strings
with open("uuids", 'r') as f:
    uuids = json.load(f)    
keys = []   # all key bytes

for uuid in uuids:
    keys.append(uuid_to_key(uuid))

# with open("keys", 'wb+') as f:
#     json.dump(keys, f)
