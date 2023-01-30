# Task 7 - Privilege Escalation - (Web Hacking, [redacted]) Points: 300


**Description:**

With access to the site, you can access most of the functionality. But there's still that admin area that's locked off.

Generate a new token value which will allow you to access the ransomware site as *an administrator*.

**Downloads:**

**Prompt:**

Enter a token value which will allow you to login as an administrator.

## Solution

In this task, we need to use our website access and gain admin level privieleges by logging into an admin's account. For that we need the token for that admin. As we saw in the previous task, the body of a token looks like this with these values:
```
row = con.execute("SELECT uid, secret from Accounts WHERE userName = ?", (userName,)).fetchone()
now = datetime.now()
exp = now + timedelta(days=30)
claims = {'iat': now,
            'exp': exp,
                    'uid': row[0],
                    'sec': row[1]}
```
We were able to generate a new token because we already knew the `uid` and `sec` values for the user. The user that we were ablet to log in as was `TiresomeSnake`.
![User info](./res/user_info.png)

The website has the following pages available to a regular user:
- Generate Key
- Unlock Request
- Admin List
- User Info
- Forum
- Admin (what we want to be able to access)

A screenshot for each page is in the folder [res](./res)

At this point, I started to experiment and look for interesting observations in the website's behaviour and I found a few things:
1. On the Generate Key page (or the `/lock` path):
   -  If I gave an input of `a*4000` it gave me an error: "Error: {demand} is not a number." on the webpage.
   -  If I gave it a shorter character input (not a number), it gave me this error on the webpage: "strconv.ParseFloat: parsing "a": invalid syntax"
2. Login page: 
   - If I logged in with a valid username such as "TiresomeSnake" or "ImpartialStranger", it would give me an internal server error.
3. I also tried sending the token with incorrect or absent keys and values. I was able to get 500 Internal Server Error with absent `uid` or `sec` or both. If the value was wrong, however, it would redirect to login.

From the Admin List page, we have the username of the admin that we want to target: `ImpartialStranger`. However, in order to forge a token, we need to have the `uid` and `sec` associated with this user. From looking at the source code from earlier, the application fetches the `uid` and `sec` values from the table `Accounts` in a DB. So, the values that we need are stored in the DB and we need to somehow get this info out of it.

While looking at the source code, I found that the `server.py` code has several calls to `subprocess.run()`; the ones in the `/lock` and `/unlock` paths seem of inerest. This got me thinking about whether I could inject some commands into it and get those to run. They take arguments from the user's request for placing into argv. However, after trying it for a while, it didn't seem to work. Incidentally, it's worthwhile to note that the actual results for those functions are generated using a different program called `keyMaster` (this will be useful in later tasks).

I also looked at the SQL queries to see if they were vulnerable to injection. But, the application uses parameterised queries.

"You know what the hardest thing about security is? The defenders have to get it right every single time. Even one mistake can give away the whole game."

Next, I was thinking of finding one place where the application was vulnerable to leaking data:
- `subprocess.run` command injection
- SQL queries: SQLi

The function `userinfo()` uses a format string for constructing the query. 
```
query = request.values.get('user')
...
with util.userdb() as con:
   infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query
   row = con.execute(infoquery).fetchone()
```
And this function is called on the `/userinfo` path.

We see that the `user` param in the GET query is the user whose information gets retrieved. So, we can get the user profile info of any user we want. For example, we can get the info of ImpartialStranger with: `https://suvwwcedmdcyelgn.ransommethis.net/znejayfsvdnrzptm/userinfo?user=ImpartialStranger`. 

**Getting the `uid`**

So, we can use SQLi in order to leak data. The way to use an SQLi to leak info from the DB is to use UNION in it. We can use this to get the `uid` of ImpartialStranger in the result of the query. We also need to determine where the value will be displayed to us. The values in the result are converted to `int` in the `userinfo()` function. So, it's okay for the uid to be in any of the result columns. The following SQL injection  will give us the `uid`
```
ImpartialStranger' UNION ALL SELECT 1 AS q, 1 AS w, uid AS e, 1 AS abc FROM Accounts WHERE userName='ImpartialStranger' ORDER BY abc;--
```
When this injection is placed into the query string, it should look like this:
```
SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='ImpartialStranger' UNION ALL SELECT 1 AS q, 1 AS w, uid AS e, 1 AS abc FROM Accounts WHERE userName='ImpartialStranger' ORDER BY abc;--
```
What this does is that it adds the result of the UNION which places `1` in all the columns except one where the `uid` is, and fetches the row for ImpartialStrager. Ordering by `abc` makes sure that the row we want is at the top. Note that I tried doing the SQLi with UNION which didn't work, but UNION ALL works. See: https://security.stackexchange.com/questions/143540/sql-injection-union-select-giving-500-internal-error

The `uid` is `3923`.

**Getting the `secret`**

Next, we need to get the `secret` from the DB. This is more difficult. The values returned in the query result are converted to `int` before sending back the response.
```
if row != None:
   userName = query
   memberSince = int(row[0])
   clientsHelped = int(row[1])
   hackersHelped = int(row[2])
   contributed = int(row[3])
```
This means that we cannot do SQLi to show the `secret` value on the webpage because it is a string and converting to an `int` will not work and cause error before it can send it back in response. We need a different approach.

If we add another WHERE clause into the SQLi query, then we can get some information by looking at whether the query was successful or not. Programmatically, we can just check if the response contains the value `3923`. Looking at the `secret` of TiresomeSnake, we can get the character set for the `secret` values. Now, we make a series of queries to check what the first character is in the `secret`, then the next, then the next and so on. 

The usual way to do such a comparison is with the LIKE clause, e.g., `secret LIKE 'a%'` . I tried that and I got a result which I tried to make a token out of, but the `secret` value is case-sensitive whereas the LIKE comparison is case-insensitive. We need a SQL comparison which is case-sensitive.

We can do case-sensitive comparison using GLOB. I found it here: https://stackoverflow.com/questions/15480319/case-sensitive-and-insensitive-like-in-sqlite#answer-64605980. The GLOB comparison uses wildcard in the unix format, meaning we need `*` not `%`.

So, the injection to use for iteratively getting each character is:
```
ImpartialStranger' UNION ALL SELECT 1 AS q, 1 AS w, uid AS e, 1 AS abc FROM Accounts WHERE userName='ImpartialStranger' AND secret GLOB '{}*' ORDER BY abc;--
```
We keep track of which character was successful in the query and then move to the next character. The script is in [x.py](./x.py).


The `secret` is `fxpIU14hMCRgBzrEHVklCfVxUYXCfswe`.

Now that we have the `uid` and the `secret`, we can make the token and login as an admin. The token generated at time of writing is: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzMzNDc5MzIsImV4cCI6MTY3NTkzOTkzMiwic2VjIjoiZnhwSVUxNGhNQ1JnQnpyRUhWa2xDZlZ4VVlYQ2Zzd2UiLCJ1aWQiOjM5MjN9.Wa1mwS5hz_qEm0ztclnzTvstwivwB1nqWeIOmSEgmpY`

Set cookies in browser console using 
```
document.cookie='tok=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzMzNDc5MzIsImV4cCI6MTY3NTkzOTkzMiwic2VjIjoiZnhwSVUxNGhNQ1JnQnpyRUhWa2xDZlZ4VVlYQ2Zzd2UiLCJ1aWQiOjM5MjN9.Wa1mwS5hz_qEm0ztclnzTvstwivwB1nqWeIOmSEgmpY;'
```

We are now an admin!

The admin page looks like this:
![admin page](./res/admin_page.png)


## Answer
- `uid` is `3923`
- `secret` is `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzMzNDc5MzIsImV4cCI6MTY3NTkzOTkzMiwic2VjIjoiZnhwSVUxNGhNQ1JnQnpyRUhWa2xDZlZ4VVlYQ2Zzd2UiLCJ1aWQiOjM5MjN9.Wa1mwS5hz_qEm0ztclnzTvstwivwB1nqWeIOmSEgmpY`

> Great! What can we find in the admin area?