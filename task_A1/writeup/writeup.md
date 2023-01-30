# Task A1 - Initial access - (Log analysis) Points: 10

**Description:**

We believe that the attacker may have gained access to the victim's network by phishing a legitimate users credentials and connecting over the company's VPN. The FBI has obtained a copy of the company's VPN server log for the week in which the attack took place. Do any of the user accounts show unusual behavior which might indicate their credentials have been compromised?
Note that all IP addresses have been anonymized.

**Downloads:**

Access log from the company's VPN server for the week in question [vpn.log](vpn.log)

**Prompt:**

Enter the username which shows signs of a possible compromise.

## Solution

In this task, we have to look for suspicious logins that can be seen in the VPN logs given to us.

The description mentions that the victim's user credentials were phished, so the attacker would be logging in in a legitimate way using those credentials. If the attacker logs in to a user's account from a different location or at an unusual time or while the true user is still logged in, then we can conclude that that account was phished.


The VPN log gives us a start time and a duration value for each login session. Using this, we can get the exact time period a user was logged in. So, let's look for any users that are logged in twice in the same time period.

The script is in [x.py](x.py).

In the script, the key thing is that if there is a user session starting before the previous one ends, then we mark it as a bad session and we can know the compromised account.

```
if end_time > next_start_time:
    bad.append(log_num)
```

When we run the script, we get the following result:
```
This user's logs have two simultaneous connections to vpn:
{'Danny.I'}

By checking if the end time of a session exceeds the login time of next session in the user's log
```

So, let's give this as the answer.

## Answer

>Nicely done! That user had two simultaneous sessions from different IP addresses. Not proof of anything, but suspicious...