from analyse_wonky import * 
from get_keys import *
from pdf_decrypt import *
from tqdm import tqdm
import numpy as np
from multiprocessing import Pool, cpu_count


def unix_to_100ns_lilian(timestamp: int):
    ts = timestamp* (10**9) # nanosec
    ts = ts // 100 # 100ns
    ts = ts + g1582ns100 # add lilian (100ns precision)
    return ts


# unix Timestamp from Log file
case_unix_timestamp = int(parser.parse("2022-06-30T11:46:51-04:00").timestamp())
# 100ns lilian timestamp
case_100ns_lilian = unix_to_100ns_lilian(case_unix_timestamp)



def generate_uuid(time_offset: int):
    node_id = "1762ad81"
    clock_seq = "b008"

    # if the lilian timestamp is: `0x1ed61fe46596c3a`
    # segments derived are : `0x1ed` , `0x61fe`, `0x46596c3a`
    # ordered as  >> low - mid - '1' + high << 
    # so uuid first 3 segments are : 46596c3a-61fe-11ed
    # and full uuid is : 46596c3a-61fe-11ed-b008-1762ad81

    timestamp = case_100ns_lilian - time_offset
    timestamp = hex(timestamp)[2:]
    ts_high = timestamp[:3]
    ts_mid = timestamp[3:7]
    ts_low = timestamp[7:]

    uuid = '-'.join([ts_low,ts_mid,'1'+ts_high,clock_seq,node_id])

    return uuid


uuids = []

# extra margin for the offset (wonkiness)
margin = 2 * (10**7) # n 100ns (2 100ns)
sec = 1 * (10 ** 7)
bound_low = int(min_100ns-margin)
bound_high = int(max_100ns+margin)

# print("Generating all uuids and keys and then decrypting and checking")
# print(f"Range checking for offset: bound_low={bound_low} bound_high={bound_high} diff={bound_high-bound_low}")

def gen_uuid_and_decrypt(offset):
    u = generate_uuid(offset)
    # print(i, u)
    k = uuid_to_key(u)
    if decrypt_pdf(k):
        print('Done',u,k)

offset_start = bound_low-margin
offset_end = bound_high+margin

print("Generating all uuids and keys and then decrypting and checking")
print(f"Range checking for offset: offset_start={offset_start} offset_end={offset_end+10*sec} diff={offset_end-offset_start}, chunksize={20}")

with Pool(cpu_count()) as p:
    # Progress bar with multiprocessing: https://stackoverflow.com/questions/41920124/multiprocessing-use-tqdm-to-display-a-progress-bar
    # list(tqdm(p.imap(gen_uuid_and_decrypt, range(offset_start, offset_end), chunksize=10), total=offset_end-offset_start))
    # list(tqdm(p.imap(gen_uuid_and_decrypt, range(0, offset_start), chunksize=10), total=offset_start))
    # list(tqdm(p.imap(gen_uuid_and_decrypt, range(offset_end, offset_end+(2*margin)), chunksize=10), total=offset_end+(2*margin) - offset_end))
    list(tqdm(p.imap(gen_uuid_and_decrypt, range(offset_start, offset_end), chunksize=20), total=offset_end-offset_start))



# Single-processing
# for i in tqdm(range(offset_start, offset_end)):
#     u = generate_uuid(i)
#     # print(i, u)
#     k = uuid_to_key(u)
#     if decrypt_pdf(k):
#         print(u,k)
#         break
# ---
