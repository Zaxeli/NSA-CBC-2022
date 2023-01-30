import time
from dateutil import parser
import datetime

# From https://github.com/google/uuid/blob/512b657a42880af87e9f0d863aa6dccf3540d4ba/time.go#L17
lillian    = 2299160          #// Julian day of 15 Oct 1582
unix       = 2440587          #// Julian day of 1 Jan 1970
epoch      = unix - lillian   #// Days between epochs
g1582      = epoch * 86400    #// seconds between epochs
g1582ns100 = g1582 * 10000000 #// 100s of a nanoseconds between epochs


# analysing uuid = 1aa3bc56-61e3-11ed-b61d-9cb6d0b80000

# getting the time
timestamp = 0x1ed61e31aa3bc56



# confirming dattime output @ https://www.uuidtools.com/decode
time_str = '2022-11-11 17:05:55.076207.0 UTC'


"""
Analysis of timestamp from all decrypted UUIDs is in analyse_uuids.py
"""