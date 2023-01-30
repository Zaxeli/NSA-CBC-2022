# Task A2 - Identifying the attacker - (Computer Forensics, Packet Analysis) Points: 40

**Description:**

Using the timestamp and IP address information from the VPN log, the FBI was able to identify a virtual server that the attacker used for staging their attack. They were able to obtain a warrant to search the server, but key files used in the attack were deleted.

Luckily, the company uses an intrusion detection system which stores packet logs. They were able to find an SSL session going to the staging server, and believe it may have been the attacker transferring over their tools.

The FBI hopes that these tools may provide a clue to the attacker's identity.

**Downloads:**

- Files captured from root's home directory on the staging server [root.tar.bz2](root.tar.bz2)
- PCAP file believed to be of the attacker downloading their tools [session.pcap](session.pcap).

**Prompt:**

What was the username of the account the attacker used when they built their tools?

## Solution

Here, we have been given some files from the attacker's home directory and we also have a pcap which is SSL encrypted. If we can decrypt the pcap, we may be able to get information about the attacker. Wireshark allows us to do this, but we will need the key for it.

Let's first decompress and open the `root/` files. We can see that there are some interesting things there which might be useful for us later on. The files `.cert.pem`, `authorized_keys` and `runwww.py` look interesting. If we look inside `runwww.py` we can see that the script is doing some things with openssl.

The script generates a file called `.cert.pem` which is the output from generating a new x509 certificate and a new private key.
```
subprocess.run(
    f'openssl req -x509 -out {certfile} -new -keyout {certfile} -newkey rsa:4096 -batch -nodes -subj /CN={cn} -days 3650',
    env=env,
    stderr=subprocess.DEVNULL,
    check=True,
    shell=True)
``` 

It then uses these to cmake a connection.

So, we have some indication that the file .cert.pem would be useful, but we need to decrypt the pcap that we have.

This link can be found with a Google search for information on how to decrypt wireshark tls pcap: https://wiki.wireshark.org/TLS 

So, the next step is to use the `.cert.pem ` file to try and decrypt the wireshark pcap. The way to do this is as follows:
1. Edit -> Preferences
2. In the left menu, go to Protocols -> TLS
3. Add the path to the `.cert.pem` file in the 'RSA keys list'
4. In the columns, add these values
   - Address: The IP address of the remote server which is being communicated to. In my case, this was `172.25.148.9`
   - Port: 443 (HTTPS default port)
   - Protocol: tls
   - Key File: path to `.cert.pem`

It should be able to decrypt it now. 

Next, we need to find the username which was used. We can do this by looking at the decrypted packets between the client and the server. Inspecting the decrypted payload of the tls packets, we can see in **packet 18** the name 'GreenRareList'. Let's try to give this as the answer.


## Answer

> Nicely done! That's a handle the FBI is familiar with.

