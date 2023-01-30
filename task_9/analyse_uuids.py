import sqlite3
from decrypt_enc_key import *
from ts_calc import *

def uuid_to_ts(uuid: bytes or str, as_num=True):
    if type(uuid) == bytes:
        uuid = uuid.decode()
    uuid = uuid.split('-')

    ts = ''
    ts += uuid[2][1:]
    ts += uuid[1] + uuid[0]
    ts = '0x' + ts

    if as_num:
        return int(ts, 16) 
    else:
        return ts

cipher = new_decryptor()

db_path = "../task_8/keyMaster.db"
conn = sqlite3.connect(db_path)

rows = conn.execute("SELECT * FROM customers WHERE NOT customerId=43772;")
rows = rows.fetchall()

decrypted = []
uuids = []
for row in rows:
    enc_uuid = row[1]

    # decrypt UUIDs
    uuid = decrypt(cipher, enc_uuid)[AES.block_size:-AES.block_size]
    uuid = uuid.decode()

    # Timestamp analysis    
    # extract all sorts of timestamp from UUID
    lillian_ts_100ns = uuid_to_ts(uuid) # 100s of nanoseconds since lillian
    unix_ts_100ns = lillian_ts_100ns - g1582ns100   # 100s of nanoseconds since unix
    unix_ts_ns = unix_ts_100ns*100
    unix_ts_sec = unix_ts_ns / (10**9) # nanosec -> sec
    dt = datetime.datetime.fromtimestamp(unix_ts_sec)
    date_str = dt.isoformat()


    insertion = list(row)
    insertion.extend([uuid])    # append decrypted UUID
    insertion.extend([lillian_ts_100ns, unix_ts_100ns, unix_ts_ns, unix_ts_sec, date_str])        # append timestamps
    
    decrypted.append(insertion)
    uuids.append(uuid)
"""
uuids:
b'ee6ca29c-6e0d-11eb-b008-1762ad81' ,
b'55e8e185-7102-11eb-b008-1762ad81' ,
b'507a2975-ac5b-11eb-b008-1762ad81' ,
b'cb711e51-2eb8-11ec-b008-1762ad81' ,
b'b983c01c-83b6-11eb-b008-1762ad81' ,
b'c9e2eb3d-660c-11ec-b008-1762ad81' ,
b'd3d6dd42-fcd7-11eb-b008-1762ad81' ,
b'9f70a18a-8b53-11eb-b008-1762ad81' ,
b'69f603ca-326e-11ec-b008-1762ad81' ,
b'948a4b91-34c7-11ec-b008-1762ad81' ,
b'0c43f9dc-14f5-11ec-b008-1762ad81' ,
b'e46c311e-3fcd-11ec-b008-1762ad81' ,
b'444fea07-ea53-11eb-b008-1762ad81' ,
b'3da1dfc2-997f-11eb-b008-1762ad81' ,
b'd87a2502-f901-11eb-b008-1762ad81' ,
b'0094e01e-7afa-11eb-b008-1762ad81' ,
b'362a31e1-b43a-11eb-b008-1762ad81' ,
b'85fd1300-7269-11eb-b008-1762ad81' ,
b'3638e475-c858-11eb-b008-1762ad81' ,
b'c0a6e128-6afd-11eb-b008-1762ad81' ,
b'd3f8e59e-eb71-11eb-b008-1762ad81' ,
b'd36733d9-4c74-11ec-b008-1762ad81' ,
b'76982f47-886d-11eb-b008-1762ad81' ,
b'27a0d6b8-c7a3-11eb-b008-1762ad81' ,
b'd9ad7bc7-6059-11ec-b008-1762ad81' ,
b'7e12a611-ab78-11eb-b008-1762ad81' ,
b'c054ddba-9127-11eb-b008-1762ad81' ,
b'a6fd726b-76aa-11eb-b008-1762ad81' ,
b'4d7ba3f5-8f25-11eb-b008-1762ad81' ,
b'6d82c0a8-3784-11ec-b008-1762ad81' ,
b'6ca66cab-63cf-11ec-b008-1762ad81' ,
b'6bd2a0de-4ee5-11ec-b008-1762ad81' ,
b'adf62e45-2835-11ec-b008-1762ad81' ,
b'c45ce77a-fc33-11eb-b008-1762ad81' ,
b'70c84119-f544-11eb-b008-1762ad81' ,
b'287edf21-55ab-11eb-b008-1762ad81' ,
b'6b011e4a-75e4-11eb-b008-1762ad81' ,
b'efc158d1-11d3-11ec-b008-1762ad81' ,
b'04f3cd8f-6377-11eb-b008-1762ad81' ,
b'643e21a6-ba57-11eb-b008-1762ad81' ,
b'f510223a-3250-11ec-b008-1762ad81' ,
b'b18806e1-a8f8-11eb-b008-1762ad81' ,
b'fa3f4cfd-8ff8-11eb-b008-1762ad81' ,
b'6e0bd557-5df1-11eb-b008-1762ad81' ,
b'ee543ffd-e975-11eb-b008-1762ad81' ,
b'f7310de8-4df1-11eb-b008-1762ad81' ,
b'9a5f0eca-5465-11ec-b008-1762ad81' ,
b'384f7073-f896-11eb-b008-1762ad81' ,
b'adee3117-7d07-11eb-b008-1762ad81' ,
"""

"""
CLOCK_SEQ is always same: 0xb008 -> version = 0b10 , clock_seq = 0x3008
Node ID is always same: 0x1762ad81
Timestamp is different
"""


# # a timestamp entry is (lillian 100ns ts, unix ts ns, unix ts sec, date string)
# timestamps = []
# for uuid in uuids:
#     lillian_ts_100ns = uuid_to_ts(uuid) # 100s of nanoseconds since lillian
#     unix_ts_100ns = lillian_ts_100ns - g1582ns100   # 100s of nanoseconds since unix

#     unix_ts_ns = unix_ts_100ns*100
#     unix_ts_sec = unix_ts_ns / (10**9) # nanosec -> sec

#     dt = datetime.datetime.fromtimestamp(unix_ts_sec)
#     date_str = dt.isoformat()

#     timestamps.append((lillian_ts_100ns, unix_ts_ns, unix_ts_sec, date_str))






