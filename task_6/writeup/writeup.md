# Task 6 - Gaining Access - (Web Hacking, [redacted]) Points: 150

**Description:**

We've found the login page on the ransomware site, but we don't know anyone's username or password. Luckily, the file you recovered from the attacker's computer looks like it could be helpful.

Generate a new token value which will allow you to access the ransomware site.

**Downloads:**

**Prompt:**

Enter a token value which will authenticate you as a user of the site.

## Solution

This taks is basically asking us to login using a valid token. The previous task gave us a Netscape HTTP Cookie file. The formatting can be understood here: https://curl.se/docs/http-cookies.html

The important information from that is that there is a cookie named `tok` and the value is the token `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM1Mzg3NTQsImV4cCI6MTY1NjEzMDc1NCwic2VjIjoiWFE4c255RXc4YXlpT1h0a0ZhcHNuQ2lrakR0bGw2MFYiLCJ1aWQiOjEwMjk0fQ.O-6pNVAqeQ7id-eZN6yH0dRay6_4QAFtMlZg2ms2-Bg`.

So, lets try decoding it as a JWT using the online decoder at https://jwt.io/. We see 3 things: the header, the payload and signature verification. The important thing is the payload:
```
{
  "iat": 1653538754,
  "exp": 1656130754,
  "sec": "XQ8snyEw8ayiOXtkFapsnCikjDtll60V",
  "uid": 10294
}
```

The values for `iat` and `exp` look like they are unix timestamps. If we convert them to GMT dates, we get, respectively, `May 26, 2022 4:19:14 AM` and `June 25, 2022 4:19:14 AM`. So, making the reasonable assumption that the `exp` value is the expiration, the problem here is that the token is expired. So, we need to forge a new token which isn't expired. But, in order to create a new JWT, we need the signing algorithm and key.

Let's go back to the source code we found in task B2. In the `util.py` file, we can see 2 functions of interest: `validate_token` and `generate_token`. In `validate_token` function is called to validate the token, and `generate_token` is used to generate a new token. We want to see if we can generate a new token which hasn't yet expired. It generates it like this:
```
row = con.execute("SELECT uid, secret from Accounts WHERE userName = ?", (userName,)).fetchone()
...
claims = {'iat': now,
        'exp': exp,
                'uid': row[0],
                'sec': row[1]}
return jwt.encode(claims, hmac_key(), algorithm='HS256')
```
The `now` and `exp` values are just the current time when generating the token and the time after 30 days from then. The `hmac_key()` function just returns a string:
```
def hmac_key():
        return "P9T43spRaRXrpB03PUpz7Wiv1d61qHqu"
```

So, now we have everything we need for the token. We can tweak the `iat` and `exp` values so that the token is fresh, we have the `uid` and `sec` values from decoding the old JWT, and we also have the `algorithm` and `hmac_key` arguments for the `jwt.encode()` call. We can just use these values in a python script to generate a fresh token. The script is in [`x.py`](./x.py)

Using this new token, we can make a a request to the website to see if we are authenticated:
```
s = requests.Session()
cookies = {'tok': token}
r = s.get(url, cookies=cookies)
```

If we want to browse the website in the browser, which is easier and recommended exploring what the website has, we can set the cookie manually in the browser. I used Cookie-Editor extension for Chrome to set a new cookie with the name `tok` and the value as the token I got from the script:
```
>>> token
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzI3NTgzNTMsImV4cCI6MTY3NTM1MDM1Mywic2VjIjoiWFE4c255RXc4YXlpT1h0a0ZhcHNuQ2lrakR0bGw2MFYiLCJ1aWQiOjEwMjk0fQ.LZownsFRqqvU2t6-YqDybE6rE5UEUedFpUPIBvmKQdY'
```

We can also set the cookies in the browser like this:
```
document.cookie = 'tok=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzI3NTgzNTMsImV4cCI6MTY3NTM1MDM1Mywic2VjIjoiWFE4c255RXc4YXlpT1h0a0ZhcHNuQ2lrakR0bGw2MFYiLCJ1aWQiOjEwMjk0fQ.LZownsFRqqvU2t6-YqDybE6rE5UEUedFpUPIBvmKQdY;'
```
and then navigate to the website url. Note that refreshing the page seems to not work, so just paste the url in the address bar and navigate there.

The website is now accessible:
![Website home](./res/website.png)


## Answer

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjYzNzM1ODgsImV4cCI6MTY2ODk2NTU4OCwic2VjIjoiWFE4c255RXc4YXlpT1h0a0ZhcHNuQ2lrakR0bGw2MFYiLCJ1aWQiOjEwMjk0fQ.Ai97bcEVZ8J4zOYAdQkHTpYyeBQdqZ_ZU2SZkhmZOSY`

(This was my answer back when I was working on it. Since the token has time embedded in it, this can be different)

> Great job! Let's see what else we can discover about the site.