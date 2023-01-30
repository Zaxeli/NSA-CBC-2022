import pandas as pd
import time
from dateutil import parser
import datetime

log = pd.read_csv("vpn.log")
# print(log)

"""Get the user logs for each user separately"""
usernames = set(log.Username)
user_logs = []
for user in usernames:
    df = log.loc[log['Username']==user]
    user_logs.append(df)


"""Look for simultaneous logins for same account"""
# anayse if start time + diration >= next start time
good = [] # user logs which are not suspicious
bad = []    # suspicious user logs

for log_num in range(len(user_logs)):
    user_log = user_logs[log_num]

    indices = user_log.index
    # print(indices)
    for i in range(len(indices)-1):
        index = indices[i]
        # print(user_log.loc[[index]])

        start_time = parser.parse(user_log['Start Time'][index]).timestamp()
        # print(i,start_time)
        duration = user_log['Duration'][index]
        if not (duration > 0):
            continue

        end_time = start_time + duration
        # print(duration, end_time)
        
        try:
            next_start_time = parser.parse(user_log['Start Time'][indices[i+1]]).timestamp()
        except:
            print(user_log[index])
            continue


        if end_time > next_start_time:
            bad.append(log_num)
    good.append(log_num)

result = f'''
This user's logs have two simultaneous connections to vpn:
{set(user_logs[bad[0]]['Username'])}

By checking if the end time of a session exceeds the login time of next session in the user's log
'''

print(result)