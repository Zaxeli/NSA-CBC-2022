import pandas as pd
from analyse_uuids import *

f_keygen_log = '../task_8/keygeneration.log'

df_keygen = pd.read_csv(f_keygen_log, header=None, names=['log_date','hacker', 'cID', 'amt'], sep='\t')
df_decrypted = pd.DataFrame(decrypted, columns=['cID','enc_key','amt', 'hacker', 'db_date', 'uuid', 'lillian_ts_100ns', 'unix_ts_100ns', 'unix_ts_ns', 'unix_ts_sec', 'ts_date'])


df_full = df_keygen.merge(df_decrypted, how='inner', on=['cID', 'hacker', 'amt'])

row0 =  list(df_full.iloc[0])
# test values
date_log = row0[0]
date_uuid = row0[-1]

def cmp_log_ts_date(row):
    dl = row[0]
    dl = parser.parse(dl)
    dl = dl.replace(tzinfo=None)
    
    dts = row[-1]
    dts = parser.parse(dts)

    return dl > dts

# log dates are always greater than uuid ts date
x = df_full.apply(cmp_log_ts_date, axis=1)



# how much is the difference
def dt_minus(row):

    dl = row[0]
    dl = parser.parse(dl)
    dl = dl.replace(tzinfo=None)

    dts = row[-1]
    dts = parser.parse(dts)

    return dl-dts

def dt_minus_100ns(row):
    log_date = row[0]
    log_ts_100ns = parser.parse(log_date)
    log_ts_100ns = log_ts_100ns.replace(tzinfo=None)
    log_ts_100ns = log_ts_100ns.timestamp()
    log_ts_100ns = log_ts_100ns * (10**7) # times 10^9 / 100 = 10^7 (100s of ns)

    unix_ts_100ns = row[-4] # The unix timestamp in 100s of ns derived from UUID

    diff = log_ts_100ns - unix_ts_100ns
    # print(unix_ts_100ns, log_ts_100ns, diff)
    return diff

    


# df_full['log_minus_ts'] = df_full.apply(dt_minus,axis=1)
df_full['log_minus_ts_100ns'] = df_full.apply(dt_minus_100ns, axis=1)

max_100ns = max(df_full['log_minus_ts_100ns']) # 118353370.0 (100ns) ~= 11.8 sec
min_100ns = min(df_full['log_minus_ts_100ns']) #  61562742.0 (100ns) ~=  6.1 sec

# make uuids using 100ns lilian timestamp with offset ranging from max_100ns to min_100ns along with some margins (1-2 sec?)