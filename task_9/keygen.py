from analyse_wonky import *

# get the time
log_dt = '2022-06-30T11:46:51-04:00'
log_dt = parser.parse(log_dt)
log_dt = log_dt.replace(tzinfo=None)

log_ts = log_dt.timestamp()

def keygen_with_ts(ts: str):
    """
    Use integer timestamp
    """
    
