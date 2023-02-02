import requests

url = 'https://suvwwcedmdcyelgn.ransommethis.net/demand'

success = []
for i in range(62818):
    r = requests.get(url, {'cid':i, 'amount':0})
    if 'amount' in r.text:
        print(i)
        success.append(i)

print(r.text)
